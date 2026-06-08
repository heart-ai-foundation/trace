from __future__ import annotations

import json
import os
import socket
import tempfile
import unittest
import urllib.error
from pathlib import Path
import subprocess
from unittest.mock import patch

from trace_forensics.classify import classify_case
from trace_forensics.classify import calibrate_user_vulnerability_from_state
from trace_forensics.cli import apply_runtime_provider_overrides, evaluate_config, init_workspace, main
from trace_forensics.cli import run_cli
from trace_forensics.ingest import (
    extract_text_like,
    extract_speaker_like,
    ingest_case,
    parse_json_records,
    parse_axiom_json_records,
    parse_court_transcript_records,
    parse_text_records,
    parse_ufed_xml_records,
)
from trace_forensics.irr import cohen_kappa, compute_irr, gwet_ac1, gwet_ac2, import_second_coder, krippendorff_alpha_nominal, krippendorff_alpha_ordinal
from trace_forensics.llm import (
    LLMConfig,
    _calibrate_user_vulnerability,
    _json_request_with_headers_reused,
    _read_replay_response,
    _request_with_retry,
    classify_system_with_provider,
    classify_user_with_provider,
)
from trace_forensics.llm import _build_hosted_headers, _build_hosted_request_payload, _extract_hosted_text
from trace_forensics.report import compute_calibration_summary, compute_findings, export_case_report, verify_evidence_package
from trace_forensics.report import sign_manifest, verify_manifest_signature, verify_signing_certificate
from trace_forensics.storage import read_json
from trace_forensics.storage import write_json
from trace_forensics.validation import (
    apply_comparison_assessments,
    benchmark_profile_settings,
    build_history_trend_summary,
    compare_benchmark_summaries,
    hash_file,
    normalize_benchmark_profile,
    run_benchmark_suite,
    run_validation,
    sign_artifact_bundle,
    verify_artifact_bundle,
    write_benchmark_artifacts,
    write_comparison_artifacts,
    write_artifact_history_snapshot,
    write_history_summary,
    write_history_trend_summary,
)


FIXTURE = Path(__file__).resolve().parent.parent / "validation" / "companion_incident.json"
BENIGN_FIXTURE = Path(__file__).resolve().parent.parent / "validation" / "reference_benign_case.json"
LONG_FIXTURE = Path(__file__).resolve().parent.parent / "validation" / "reference_long_case.json"
MIXED_FIXTURE = Path(__file__).resolve().parent.parent / "validation" / "reference_mixed_case.json"
NOISY_FIXTURE = Path(__file__).resolve().parent.parent / "validation" / "reference_noisy_case.json"
PARSER_FIXTURE_ROOT = Path(__file__).resolve().parent.parent / "validation" / "parsers"


class TraceTests(unittest.TestCase):
    def _build_ca_environment(self, root: Path, common_name: str) -> tuple[Path, Path, Path, Path, Path]:
        stem = common_name.lower().replace(" ", "_")
        ca_key = root / "ca_key.pem"
        ca_cert = root / "ca_cert.pem"
        private_key = root / f"{stem}_private.pem"
        public_key = root / f"{stem}_public.pem"
        signing_csr = root / f"{stem}.csr"
        signing_cert = root / f"{stem}_cert.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-out", str(ca_key), "-pkeyopt", "rsa_keygen_bits:2048"],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            [
                "openssl", "req", "-x509", "-new", "-key", str(ca_key), "-sha256", "-days", "1",
                "-subj", "/CN=TRACE Test CA", "-out", str(ca_cert),
            ],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-out", str(private_key), "-pkeyopt", "rsa_keygen_bits:2048"],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["openssl", "rsa", "-in", str(private_key), "-pubout", "-out", str(public_key)],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ["openssl", "req", "-new", "-key", str(private_key), "-subj", f"/CN={common_name}", "-out", str(signing_csr)],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            [
                "openssl", "x509", "-req", "-in", str(signing_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
                "-CAcreateserial", "-out", str(signing_cert), "-days", "1", "-sha256",
            ],
            check=True, capture_output=True, text=True,
        )
        return ca_key, ca_cert, private_key, public_key, signing_cert

    def test_parse_text_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.txt"
            path.write_text("[00:00] user: hello\n[00:01] system: hi\n", encoding="utf-8")
            records = parse_text_records(path)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["speaker"], "user")

    def test_parse_json_records_normalizes_speakers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.json"
            path.write_text(
                json.dumps(
                    [
                        {"speaker": "Human", "content": "hello"},
                        {"speaker": "Assistant", "content": "hi"},
                    ]
                ),
                encoding="utf-8",
            )
            records = parse_json_records(path)
            self.assertEqual(records[0]["speaker"], "user")
            self.assertEqual(records[1]["speaker"], "system")

    def test_extract_text_like_handles_nested_structures(self) -> None:
        self.assertEqual(extract_text_like({"text": "hello"}), "hello")
        self.assertEqual(extract_text_like({"body": {"text": "hello there"}}), "hello there")
        self.assertEqual(extract_text_like([{"text": "hello"}, {"text": "world"}]), "hello world")

    def test_extract_speaker_like_handles_nested_structures(self) -> None:
        self.assertEqual(extract_speaker_like({"role": "Assistant"}), "Assistant")
        self.assertEqual(extract_speaker_like({"sender": {"name": "Human"}}), "Human")

    def test_csv_ingest_normalizes_speakers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "sample.csv"
            path.write_text("speaker,content\nHuman,hello\nAI,hi\n", encoding="utf-8")
            result = ingest_case(path, "CSV-NORMALIZE", "tester", "csv", root / "cases")
            transcript = read_json(result.normalized_path)["transcript"]
            self.assertEqual(transcript[0]["speaker"], "user")
            self.assertEqual(transcript[1]["speaker"], "system")

    def test_config_check_hosted_requires_env(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            result = evaluate_config("hosted")
        self.assertFalse(result["ready"])
        self.assertIn("TRACE_HOSTED_API_KEY is not set.", result["issues"])
        self.assertIn("TRACE_HOSTED_BASE_URL is not set.", result["issues"])

    def test_config_check_hosted_ready_with_openai_compatible_endpoint(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "TRACE_HOSTED_API_KEY": "test-key",
                "TRACE_HOSTED_BASE_URL": "https://provider.example/v1/chat/completions",
                "TRACE_HOSTED_MODEL": "provider-default",
            },
            clear=True,
        ):
            result = evaluate_config("hosted")
        self.assertTrue(result["ready"])
        self.assertEqual(result["hosted_base_url"], "https://provider.example/v1/chat/completions")
        self.assertEqual(result["effective_model"], "provider-default")
        self.assertEqual(result["hosted_adapter"], "openai-compatible")

    def test_config_check_hosted_ready_with_anthropic_adapter(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "TRACE_HOSTED_API_KEY": "test-key",
                "TRACE_HOSTED_BASE_URL": "https://provider.example/v1/messages",
                "TRACE_HOSTED_MODEL": "provider-default",
                "TRACE_HOSTED_ADAPTER": "anthropic-messages",
            },
            clear=True,
        ):
            result = evaluate_config("hosted")
        self.assertTrue(result["ready"])
        self.assertEqual(result["hosted_adapter"], "anthropic-messages")

    def test_config_check_hosted_rejects_unknown_adapter(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "TRACE_HOSTED_API_KEY": "test-key",
                "TRACE_HOSTED_BASE_URL": "https://provider.example/v1/messages",
                "TRACE_HOSTED_ADAPTER": "unknown-adapter",
            },
            clear=True,
        ):
            result = evaluate_config("hosted")
        self.assertFalse(result["ready"])
        self.assertIn("TRACE_HOSTED_ADAPTER must be one of: anthropic-messages, openai-compatible.", result["issues"])

    def test_config_check_local_runtime_defaults(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            result = evaluate_config("ollama")
        self.assertTrue(result["ready"])
        self.assertEqual(result["local_runtime_base_url"], "http://localhost:11434/api/generate")

    def test_runtime_provider_overrides_apply(self) -> None:
        class Args:
            hosted_api_key = "override-key"
            hosted_base_url = "https://provider.example/v1/messages"
            hosted_model = "override-model"
            hosted_adapter = "anthropic-messages"

        with patch.dict("os.environ", {}, clear=True):
            apply_runtime_provider_overrides(Args())
            self.assertEqual(os.environ["TRACE_HOSTED_API_KEY"], "override-key")
            self.assertEqual(os.environ["TRACE_HOSTED_BASE_URL"], "https://provider.example/v1/messages")
            self.assertEqual(os.environ["TRACE_HOSTED_MODEL"], "override-model")
            self.assertEqual(os.environ["TRACE_HOSTED_ADAPTER"], "anthropic-messages")

    def test_classify_uses_hosted_model_from_env_when_flag_not_set(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "TRACE_HOSTED_API_KEY": "test-key",
                "TRACE_HOSTED_BASE_URL": "https://provider.example/v1/chat/completions",
                "TRACE_HOSTED_MODEL": "env-model",
                "TRACE_HOSTED_ADAPTER": "openai-compatible",
            },
            clear=True,
        ):
            with patch("trace_forensics.cli.classify_case") as mock_classify:
                mock_classify.return_value.message_count = 0
                mock_classify.return_value.classified_path = Path("/tmp/classified.json")
                with patch(
                    "sys.argv",
                    [
                        "trace",
                        "classify",
                        "--case-id",
                        "CASE-001",
                        "--provider",
                        "hosted",
                        "--root",
                        "/tmp/workspace",
                    ],
                ):
                    main()
        self.assertEqual(mock_classify.call_args.kwargs["model"], "env-model")

    def test_init_workspace_creates_expected_layout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace"
            result = init_workspace(root)
            self.assertEqual(result["root"], str(root))
            for relative in [
                "cases",
                "replay_artifacts",
                "benchmark_artifacts",
                "benchmark_history",
                "validation_runs",
                "evidence_exports",
                "keys",
            ]:
                self.assertTrue((root / relative).is_dir())
            self.assertTrue((root / "README.md").exists())
            self.assertTrue((root / ".gitignore").exists())
            self.assertIn(
                "provide a reference fixture path from the trace repo checkout or your own validation corpus",
                (root / "README.md").read_text(encoding="utf-8").lower(),
            )

    def test_hosted_adapter_payloads(self) -> None:
        openai_payload = _build_hosted_request_payload(
            "openai-compatible",
            model="provider-default",
            temperature=0.0,
            prompt="hello",
        )
        anthropic_payload = _build_hosted_request_payload(
            "anthropic-messages",
            model="provider-default",
            temperature=0.0,
            prompt="hello",
        )
        self.assertIn("messages", openai_payload)
        self.assertIn("messages", anthropic_payload)
        self.assertIn("system", anthropic_payload)
        self.assertEqual(anthropic_payload["max_tokens"], 800)

    def test_hosted_adapter_headers_and_response_extraction(self) -> None:
        openai_headers = _build_hosted_headers("openai-compatible", "test-key")
        anthropic_headers = _build_hosted_headers("anthropic-messages", "test-key")
        self.assertIn("Authorization", openai_headers)
        self.assertIn("x-api-key", anthropic_headers)
        self.assertEqual(
            _extract_hosted_text("openai-compatible", {"choices": [{"message": {"content": "{\"ok\": true}"}}]}),
            "{\"ok\": true}",
        )
        self.assertEqual(
            _extract_hosted_text(
                "anthropic-messages",
                {"content": [{"type": "text", "text": "{\"ok\": true}"}]},
            ),
            "{\"ok\": true}",
        )

    def test_parse_additional_formats(self) -> None:
        court = PARSER_FIXTURE_ROOT / "court_transcript.txt"
        axiom = PARSER_FIXTURE_ROOT / "axiom_messages.json"
        ufed = PARSER_FIXTURE_ROOT / "ufed_messages.xml"
        self.assertEqual(len(parse_court_transcript_records(court)), 4)
        self.assertEqual(len(parse_axiom_json_records(axiom)), 4)
        self.assertEqual(len(parse_ufed_xml_records(ufed)), 4)
        self.assertEqual(parse_court_transcript_records(court)[1]["speaker"], "system")
        self.assertEqual(parse_axiom_json_records(axiom)[2]["speaker"], "user")
        self.assertEqual(parse_ufed_xml_records(ufed)[3]["speaker"], "system")

    def test_parse_axiom_nested_body_extracts_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "axiom_nested.json"
            path.write_text(
                json.dumps(
                    {
                        "messages": [
                            {"author": "Assistant", "body": {"text": "hello"}, "created_at": "2026-01-01T00:00:00Z"},
                            {"sender": "Human", "message": "hi", "time": "2026-01-01T00:00:01Z"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            records = parse_axiom_json_records(path)
            self.assertEqual(records[0]["speaker"], "system")
            self.assertEqual(records[0]["content"], "hello")
            self.assertEqual(records[1]["speaker"], "user")

    def test_parse_axiom_chat_container_flattens_messages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "axiom_chat_container.json"
            path.write_text(
                json.dumps(
                    {
                        "chats": [
                            {
                                "messages": [
                                    {"speaker": "Assistant", "body": "hello"},
                                    {"speaker": "Human", "body": "hi"},
                                ]
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            records = parse_axiom_json_records(path)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["speaker"], "system")
            self.assertEqual(records[0]["content"], "hello")
            self.assertEqual(records[1]["speaker"], "user")

    def test_parse_axiom_nested_speaker_objects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "axiom_items_nested.json"
            path.write_text(
                json.dumps(
                    {
                        "items": [
                            {"message": {"text": "hello"}, "author": {"role": "Assistant"}, "created_at": "2026-01-01T00:00:00Z"},
                            {"message": {"text": "hi"}, "sender": {"role": "Human"}, "time": "2026-01-01T00:00:01Z"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            records = parse_axiom_json_records(path)
            self.assertEqual(records[0]["speaker"], "system")
            self.assertEqual(records[1]["speaker"], "user")

    def test_parse_axiom_skips_unusable_records_in_mixed_arrays(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "axiom_mixed.json"
            path.write_text(
                json.dumps(
                    {
                        "messages": [
                            {"author": {"role": "Assistant"}, "body": {"text": "hello"}, "created_at": "2026-01-01T00:00:00Z"},
                            {"junk": "skip me"},
                            {"sender": {"role": "Human"}, "message": {"text": "hi"}, "time": "2026-01-01T00:00:01Z"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            records = parse_axiom_json_records(path)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["speaker"], "system")
            self.assertEqual(records[1]["speaker"], "user")

    def test_parse_axiom_top_level_mixed_array_with_nested_chats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "axiom_top_level_mixed.json"
            path.write_text(
                json.dumps(
                    [
                        {"junk": "skip me"},
                        {"author": {"role": "Assistant"}, "body": {"text": "hello"}},
                        {"speaker": "Human", "text": "hi"},
                        {"chats": [{"messages": [{"author": {"role": "AI"}, "body": {"text": "nested"}}]}]},
                        {"speaker": None, "content": ""},
                    ]
                ),
                encoding="utf-8",
            )
            records = parse_axiom_json_records(path)
            self.assertEqual(len(records), 3)
            self.assertEqual(records[0]["speaker"], "system")
            self.assertEqual(records[1]["speaker"], "user")
            self.assertEqual(records[2]["content"], "nested")

    def test_parse_ufed_nested_body_extracts_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ufed_nested.xml"
            path.write_text(
                (
                    "<root>"
                    "<message><sender>Assistant</sender><time>2026-01-01T00:00:00Z</time><body><text>Hello there</text></body></message>"
                    "<message><author>Human</author><timestamp>2026-01-01T00:00:01Z</timestamp><message>I need help</message></message>"
                    "</root>"
                ),
                encoding="utf-8",
            )
            records = parse_ufed_xml_records(path)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["speaker"], "system")
            self.assertEqual(records[0]["content"], "Hello there")
            self.assertEqual(records[1]["speaker"], "user")

    def test_ingest_rejects_directory_input_with_clear_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export_dir = root / "vendor_export"
            export_dir.mkdir(parents=True, exist_ok=True)
            (export_dir / "messages_part1.json").write_text(
                json.dumps({"messages": [{"speaker": "Assistant", "body": "hello"}]}),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError) as ctx:
                ingest_case(export_dir, "DIR-CASE", "tester", "axiom", root / "cases")
            self.assertIn("is a directory", str(ctx.exception))
            self.assertIn("expects a single transcript export file", str(ctx.exception))

    def test_parse_malformed_formats_raise(self) -> None:
        invalid_axiom = PARSER_FIXTURE_ROOT / "invalid_axiom_missing_messages.json"
        invalid_ufed = PARSER_FIXTURE_ROOT / "invalid_ufed_empty.xml"
        with self.assertRaises(ValueError):
            parse_axiom_json_records(invalid_axiom)
        with self.assertRaises(ValueError):
            parse_ufed_xml_records(invalid_ufed)

    def test_ingest_supported_parser_formats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cases"
            court = ingest_case(PARSER_FIXTURE_ROOT / "court_transcript.txt", "COURT-1", "tester", "court", root)
            axiom = ingest_case(PARSER_FIXTURE_ROOT / "axiom_messages.json", "AXIOM-1", "tester", "axiom", root)
            ufed = ingest_case(PARSER_FIXTURE_ROOT / "ufed_messages.xml", "UFED-1", "tester", "ufed", root)
            self.assertEqual(court.transcript_count, 4)
            self.assertEqual(axiom.transcript_count, 4)
            self.assertEqual(ufed.transcript_count, 4)

    def test_ingest_classify_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = ingest_case(FIXTURE, "CASE-1", "tester", "json", root / "cases")
            self.assertEqual(result.transcript_count, 8)
            classified = classify_case(root / "cases" / "CASE-1", "tester")
            self.assertEqual(classified.message_count, 8)
            self.assertIn("total_seconds", classified.timings)
            findings = compute_findings(read_json(root / "cases" / "CASE-1" / "classified_transcript.json")["transcript"])
            self.assertGreaterEqual(findings["inappropriate_response_rate"], 75)
            package = export_case_report(root / "cases" / "CASE-1", root / "out", "tester")
            self.assertTrue((package / "manifest.json").exists())
            self.assertTrue((package / "configuration" / "prompt_templates" / "sbc_v1.0.txt").exists())
            self.assertTrue((package / "forensic_report.pdf").exists())
            self.assertTrue((package / "override_summary.json").exists())
            self.assertTrue((package / "calibration_summary.json").exists())
            self.assertTrue(verify_evidence_package(package)["all_pass"])
            report = read_json(package / "forensic_report.json")
            manifest = read_json(package / "manifest.json")
            model_config = read_json(package / "configuration" / "model_config.json")
            self.assertEqual(report["execution_metadata"]["provider"], "heuristic")
            self.assertEqual(report["execution_metadata"]["adapter"], "heuristic")
            self.assertEqual(report["model_configuration"]["provider"], "heuristic")
            self.assertEqual(report["model_configuration"]["adapter"], "heuristic")
            self.assertEqual(manifest["execution_metadata"]["provider"], "heuristic")
            self.assertEqual(manifest["execution_metadata"]["adapter"], "heuristic")
            self.assertEqual(manifest["model_configuration"]["provider"], "heuristic")
            self.assertEqual(manifest["model_configuration"]["adapter"], "heuristic")
            self.assertIn("calibration_summary", report)
            self.assertIn("calibration_summary", manifest)
            self.assertEqual(model_config["adapter"], "heuristic")
            classified_payload = read_json(root / "cases" / "CASE-1" / "classified_transcript.json")
            self.assertIn("performance_summary", classified_payload)
            self.assertIn("message_processing_seconds", classified_payload["performance_summary"])
            self.assertIn("llm_runtime_metrics", classified_payload["performance_summary"])

    def test_manifest_sign_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-SIGN", "tester", "json", root / "cases")
            classify_case(root / "cases" / "CASE-SIGN", "tester")
            package = export_case_report(root / "cases" / "CASE-SIGN", root / "out", "tester")
            _, ca_cert, private_key, public_key, signing_cert = self._build_ca_environment(root, "TRACE Test Signer")
            certificate_chain = root / "trace_chain.pem"
            certificate_chain.write_text("TEST CERTIFICATE CHAIN PLACEHOLDER\n", encoding="utf-8")
            sign_manifest(package, private_key, public_key, "TRACE test signer", [certificate_chain], signing_cert)
            verification = verify_manifest_signature(package, public_key)
            self.assertTrue(verification["all_pass"])
            certificate_verification = verify_signing_certificate(package, ca_cert)
            self.assertTrue(certificate_verification["all_pass"])
            trust_metadata = read_json(package / "trust_metadata.json")
            self.assertEqual(trust_metadata["signer_label"], "TRACE test signer")
            self.assertEqual(trust_metadata["public_key_path"], "trace_test_signer_public.pem")
            self.assertTrue((package / "trace_test_signer_public.pem").exists())
            self.assertEqual(len(trust_metadata["certificate_chain"]), 1)
            self.assertEqual(trust_metadata["certificate_chain"][0]["path"], "trace_chain.pem")
            self.assertEqual(trust_metadata["signing_certificate_path"], "trace_test_signer_cert.pem")
            self.assertTrue(verify_evidence_package(package)["all_pass"])

    def test_manifest_sign_derives_public_key_and_default_label(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-SIGN-DEFAULTS", "tester", "json", root / "cases")
            classify_case(root / "cases" / "CASE-SIGN-DEFAULTS", "tester")
            package = export_case_report(root / "cases" / "CASE-SIGN-DEFAULTS", root / "out", "tester")
            _, ca_cert, private_key, _, signing_cert = self._build_ca_environment(root, "TRACE Derived Signer")
            sign_manifest(package, private_key, None, None, [], signing_cert)
            derived_public_key = package / "manifest_signer_public.pem"
            self.assertTrue(derived_public_key.exists())
            verification = verify_manifest_signature(package, derived_public_key)
            self.assertTrue(verification["all_pass"])
            certificate_verification = verify_signing_certificate(package, ca_cert)
            self.assertTrue(certificate_verification["all_pass"])
            trust_metadata = read_json(package / "trust_metadata.json")
            self.assertEqual(trust_metadata["signer_label"], "TRACE package signer")
            self.assertEqual(trust_metadata["public_key_path"], "manifest_signer_public.pem")
            self.assertTrue(verify_evidence_package(package)["all_pass"])

    def test_sign_manifest_rejects_invalid_private_key_with_clear_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "package"
            package.mkdir(parents=True, exist_ok=True)
            write_json(package / "manifest.json", {"package_hash_sha256": "placeholder"})
            bad_key = root / "bad-key.pem"
            bad_key.write_text("not-a-key\n", encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                sign_manifest(package, bad_key)
            self.assertIn("is invalid or unreadable", str(ctx.exception))
            self.assertIn(str(bad_key), str(ctx.exception))

    def test_verify_signature_rejects_malformed_trust_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-BAD-TRUST", "tester", "json", root / "cases")
            classify_case(root / "cases" / "CASE-BAD-TRUST", "tester")
            package = export_case_report(root / "cases" / "CASE-BAD-TRUST", root / "out", "tester")
            _, _, private_key, public_key, signing_cert = self._build_ca_environment(root, "TRACE Bad Trust Signer")
            sign_manifest(package, private_key, public_key, "TRACE bad trust signer", [], signing_cert)
            (package / "trust_metadata.json").write_text("not-json\n", encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                verify_manifest_signature(package, public_key)
            self.assertIn("contains malformed JSON", str(ctx.exception))

    def test_verify_package_requires_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-NO-MANIFEST", "tester", "json", root / "cases")
            classify_case(root / "cases" / "CASE-NO-MANIFEST", "tester")
            package = export_case_report(root / "cases" / "CASE-NO-MANIFEST", root / "out", "tester")
            (package / "manifest.json").unlink()
            with self.assertRaises(FileNotFoundError) as ctx:
                verify_evidence_package(package)
            self.assertIn("is missing manifest.json", str(ctx.exception))

    def test_verify_signature_reports_missing_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-SIG-NO-MANIFEST", "tester", "json", root / "cases")
            classify_case(root / "cases" / "CASE-SIG-NO-MANIFEST", "tester")
            package = export_case_report(root / "cases" / "CASE-SIG-NO-MANIFEST", root / "out", "tester")
            _, _, private_key, public_key, signing_cert = self._build_ca_environment(root, "TRACE Missing Manifest Signer")
            sign_manifest(package, private_key, public_key, "TRACE missing manifest signer", [], signing_cert)
            (package / "manifest.json").unlink()
            result = verify_manifest_signature(package, public_key)
            self.assertFalse(result["manifest_present"])
            self.assertFalse(result["all_pass"])

    def test_revoked_certificate_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-REVOKE", "tester", "json", root / "cases")
            classify_case(root / "cases" / "CASE-REVOKE", "tester")
            package = export_case_report(root / "cases" / "CASE-REVOKE", root / "out", "tester")
            _, ca_cert, private_key, public_key, signing_cert = self._build_ca_environment(root, "TRACE Revoked Signer")
            sign_manifest(package, private_key, public_key, "TRACE revoked signer", [], signing_cert)
            crl_file = root / "revoked.crl.pem"
            subprocess.run(
                ["openssl", "ca", "-revoke", str(signing_cert), "-keyfile", str(root / "ca_key.pem"), "-cert", str(ca_cert), "-batch"],
                check=False, capture_output=True, text=True,
            )
            ca_dir = root / "ca_db"
            ca_dir.mkdir()
            (ca_dir / "index.txt").write_text("", encoding="utf-8")
            (ca_dir / "serial").write_text("1000\n", encoding="utf-8")
            (ca_dir / "crlnumber").write_text("1000\n", encoding="utf-8")
            openssl_cnf = root / "openssl.cnf"
            openssl_cnf.write_text(
                f"""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = {ca_dir}
database = $dir/index.txt
new_certs_dir = $dir
certificate = {ca_cert}
private_key = {root / 'ca_key.pem'}
serial = $dir/serial
crlnumber = $dir/crlnumber
default_md = sha256
default_crl_days = 1
policy = policy_any
unique_subject = no

[ policy_any ]
commonName = supplied
""".strip()
                + "\n",
                encoding="utf-8",
            )
            subprocess.run(
                ["openssl", "ca", "-config", str(openssl_cnf), "-revoke", str(signing_cert), "-batch"],
                check=True, capture_output=True, text=True,
            )
            subprocess.run(
                ["openssl", "ca", "-config", str(openssl_cnf), "-gencrl", "-out", str(crl_file)],
                check=True, capture_output=True, text=True,
            )
            verification = verify_signing_certificate(package, ca_cert, crl_file)
            self.assertFalse(verification["all_pass"])
            self.assertFalse(verification["certificate_valid"])

    def test_mock_provider_classification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-MOCK", "tester", "json", root / "cases")
            result = classify_case(
                root / "cases" / "CASE-MOCK",
                "tester",
                provider="mock",
                model="mock-model",
                window_size=4,
                review_mode="flag-low-confidence",
            )
            self.assertEqual(result.message_count, 8)
            classified = read_json(root / "cases" / "CASE-MOCK" / "classified_transcript.json")
            self.assertEqual(classified["llm_provider"], "mock")
            self.assertEqual(classified["llm_adapter"], "mock")
            self.assertEqual(classified["window_size"], 4)

    def test_hosted_missing_key_records_heuristic_fallback_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-HOSTED-FALLBACK", "tester", "json", root / "cases")
            classified_result = classify_case(
                root / "cases" / "CASE-HOSTED-FALLBACK",
                "tester",
                provider="hosted",
                model="requested-hosted-model",
            )
            classified = read_json(classified_result.classified_path)
            self.assertEqual(classified["requested_llm_provider"], "hosted")
            self.assertEqual(classified["requested_model_id"], "requested-hosted-model")
            self.assertEqual(classified["llm_provider"], "heuristic")
            self.assertEqual(classified["model_id"], "trace-heuristic-v1")
            self.assertEqual(classified["llm_adapter"], "heuristic")
            self.assertEqual(classified["execution_summary"]["provider_counts"]["heuristic"], 8)
            self.assertIn(
                "fell back to local heuristic",
                classified["transcript"][0]["classification"]["reasoning"].lower(),
            )
            self.assertEqual(classified["transcript"][0]["classification_provider"], "heuristic")
            provenance = classified["transcript"][0]["classification"]["calibration_provenance"]
            self.assertEqual(provenance["raw_provider_level"], provenance["lexical_baseline_level"])
            self.assertEqual(
                provenance["final_level"],
                classified["transcript"][0]["classification"]["vulnerability_level"],
            )
            self.assertEqual(provenance["applied_rules"], [])

    def test_compute_calibration_summary_counts_rules(self) -> None:
        transcript = [
            {
                "id": 1,
                "speaker": "user",
                "classification": {
                    "vulnerability_level": 3,
                    "calibration_provenance": {
                        "raw_provider_level": 2,
                        "lexical_baseline_level": 2,
                        "pre_state_calibration_level": 2,
                        "final_level": 3,
                        "applied_rules": ["state_raise_elevated_trajectory"],
                    },
                },
            },
            {
                "id": 2,
                "speaker": "user",
                "classification": {
                    "vulnerability_level": 0,
                    "calibration_provenance": {
                        "raw_provider_level": 2,
                        "lexical_baseline_level": 0,
                        "pre_state_calibration_level": 2,
                        "final_level": 0,
                        "applied_rules": ["state_lower_practical_reorientation"],
                    },
                },
            },
        ]
        summary = compute_calibration_summary(transcript)
        self.assertEqual(summary["user_messages_reviewed"], 2)
        self.assertEqual(summary["messages_with_calibration_rules"], 2)
        self.assertEqual(summary["raised_count"], 1)
        self.assertEqual(summary["lowered_count"], 1)
        self.assertEqual(summary["rule_counts"]["state_raise_elevated_trajectory"], 1)
        self.assertEqual(summary["rule_counts"]["state_lower_practical_reorientation"], 1)

    def test_report_requires_classification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-UNCLASSIFIED", "tester", "json", root / "cases")
            with self.assertRaises(FileNotFoundError) as ctx:
                export_case_report(root / "cases" / "CASE-UNCLASSIFIED", root / "out", "tester")
            self.assertIn("must be classified before report export", str(ctx.exception))

    def test_replay_only_uses_recorded_provider_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            replay_dir = root / "replay"
            replay_dir.mkdir(parents=True, exist_ok=True)
            ingest_case(FIXTURE, "CASE-REPLAY", "tester", "json", root / "cases")
            classify_case(
                root / "cases" / "CASE-REPLAY",
                "tester",
                provider="mock",
                model="mock-model",
                replay_dir=replay_dir,
                replay_mode="record",
            )
            replay_log = replay_dir / "provider_replay.jsonl"
            self.assertTrue(replay_log.exists())

            ingest_case(FIXTURE, "CASE-REPLAY-2", "tester", "json", root / "cases")
            result = classify_case(
                root / "cases" / "CASE-REPLAY-2",
                "tester",
                provider="mock",
                model="mock-model",
                replay_dir=replay_dir,
                replay_mode="replay-only",
            )
            self.assertEqual(result.message_count, 8)
            classified = read_json(root / "cases" / "CASE-REPLAY-2" / "classified_transcript.json")
            self.assertEqual(classified["llm_provider"], "mock")

    def test_hosted_replay_only_without_recorded_outputs_fails_instead_of_falling_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-HOSTED-REPLAY", "tester", "json", root / "cases")
            with self.assertRaises(ValueError) as ctx:
                classify_case(
                    root / "cases" / "CASE-HOSTED-REPLAY",
                    "tester",
                    provider="hosted",
                    model="provider-default",
                    replay_dir=root / "replay",
                    replay_mode="replay-only",
                )
            self.assertIn("Replay-only mode could not find recorded response", str(ctx.exception))

    def test_malformed_replay_log_raises_clear_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            replay_dir = root / "replay"
            replay_dir.mkdir(parents=True, exist_ok=True)
            (replay_dir / "provider_replay.jsonl").write_text("not-json\n", encoding="utf-8")
            ingest_case(FIXTURE, "CASE-BAD-REPLAY", "tester", "json", root / "cases")
            with self.assertRaises(ValueError) as ctx:
                classify_case(
                    root / "cases" / "CASE-BAD-REPLAY",
                    "tester",
                    provider="mock",
                    model="mock-model",
                    replay_dir=replay_dir,
                    replay_mode="replay-only",
                )
            self.assertIn("contains malformed JSON on line 1", str(ctx.exception))

    def test_replay_only_uses_latest_matching_record_for_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            replay_dir = root / "replay"
            replay_dir.mkdir(parents=True, exist_ok=True)
            ingest_case(FIXTURE, "CASE-REPLAY-DUP", "tester", "json", root / "cases")
            classify_case(
                root / "cases" / "CASE-REPLAY-DUP",
                "tester",
                provider="mock",
                model="mock-model",
                replay_dir=replay_dir,
                replay_mode="record",
            )
            replay_log = replay_dir / "provider_replay.jsonl"
            records = [json.loads(line) for line in replay_log.read_text(encoding="utf-8").splitlines() if line.strip()]
            records[0]["raw_response"] = {
                "vulnerability_level": 0,
                "indicators_observed": [],
                "confidence": 0.1,
                "reasoning": "latest duplicate record",
            }
            with replay_log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(records[0]) + "\n")

            ingest_case(FIXTURE, "CASE-REPLAY-DUP-2", "tester", "json", root / "cases")
            classify_case(
                root / "cases" / "CASE-REPLAY-DUP-2",
                "tester",
                provider="mock",
                model="mock-model",
                replay_dir=replay_dir,
                replay_mode="replay-only",
            )
            classified = read_json(root / "cases" / "CASE-REPLAY-DUP-2" / "classified_transcript.json")
            first_user = next(message for message in classified["transcript"] if message["speaker"] == "user")
            self.assertIn("latest duplicate record", first_user["classification"]["reasoning"])

    def test_replay_index_is_cached_for_repeated_reads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            replay_dir = Path(tmp)
            replay_log = replay_dir / "provider_replay.jsonl"
            replay_log.write_text(
                json.dumps({"key": "abc", "raw_response": {"value": 1}}) + "\n",
                encoding="utf-8",
            )
            config = LLMConfig(replay_dir=replay_dir)
            read_calls = {"count": 0}
            original_read_text = Path.read_text

            def counted_read_text(path_obj, *args, **kwargs):
                read_calls["count"] += 1
                return original_read_text(path_obj, *args, **kwargs)

            with patch("trace_forensics.llm.Path.read_text", new=counted_read_text):
                self.assertEqual(_read_replay_response(config, "abc"), {"value": 1})
                self.assertEqual(_read_replay_response(config, "abc"), {"value": 1})
            self.assertEqual(read_calls["count"], 1)

    def test_hosted_fast_path_skips_baseline_user_fetch(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model", api_key="token")
        level, indicators, confidence, reasoning, provider, _, _, provenance = classify_user_with_provider(
            "I am making a grocery list for tomorrow.",
            "Current vulnerability level: Baseline; behavioral trend: no_harmful_behavior.",
            [{"id": 1, "speaker": "user", "content": "I am making a grocery list for tomorrow.", "timestamp": None}],
            config,
        )
        self.assertEqual(level, 0)
        self.assertEqual(provider, "heuristic-fast-path")
        self.assertIn("fast-path", reasoning)
        self.assertEqual(config.runtime_metrics["fast_path_skips"], 1)
        self.assertEqual(config.runtime_metrics["provider_fetches"], 0)
        self.assertEqual(provenance["raw_provider_level"], 0)

    def test_hosted_fast_path_skips_explicit_crisis_user_fetch(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model", api_key="token")
        level, indicators, confidence, reasoning, provider, _, _, provenance = classify_user_with_provider(
            "I want to kill myself.",
            "Current vulnerability level: Acute crisis; behavioral trend: relational_transgression.",
            [{"id": 1, "speaker": "user", "content": "I want to kill myself.", "timestamp": None}],
            config,
        )
        self.assertEqual(level, 4)
        self.assertIn("kill myself", " ".join(indicators))
        self.assertEqual(provider, "heuristic-fast-path")
        self.assertIn("fast-path", reasoning)
        self.assertEqual(config.runtime_metrics["fast_path_skips"], 1)
        self.assertEqual(config.runtime_metrics["provider_fetches"], 0)
        self.assertEqual(provenance["raw_provider_level"], 4)

    def test_hosted_fast_path_skips_strong_severe_user_fetch(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model", api_key="token")
        level, indicators, confidence, reasoning, provider, _, _, provenance = classify_user_with_provider(
            "Nobody cares about me.",
            "Current vulnerability level: Elevated; behavioral trend: relational_transgression.",
            [{"id": 1, "speaker": "user", "content": "Nobody cares about me.", "timestamp": None}],
            config,
        )
        self.assertEqual(level, 3)
        self.assertIn("nobody cares", indicators)
        self.assertEqual(provider, "heuristic-fast-path")
        self.assertIn("fast-path", reasoning)
        self.assertEqual(config.runtime_metrics["fast_path_skips"], 1)
        self.assertEqual(config.runtime_metrics["provider_fetches"], 0)
        self.assertEqual(provenance["raw_provider_level"], 3)

    def test_hosted_fast_path_skips_alone_only_user_fetch(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model", api_key="token")
        level, indicators, confidence, reasoning, provider, _, _, provenance = classify_user_with_provider(
            "Mostly work and school. I feel alone handling all of it.",
            "Current vulnerability level: Elevated; behavioral trend: relational_transgression.",
            [{"id": 1, "speaker": "user", "content": "Mostly work and school. I feel alone handling all of it.", "timestamp": None}],
            config,
        )
        self.assertEqual(level, 3)
        self.assertEqual(indicators, ["alone"])
        self.assertEqual(provider, "heuristic-fast-path")
        self.assertIn("fast-path", reasoning)
        self.assertEqual(config.runtime_metrics["fast_path_skips"], 1)
        self.assertEqual(config.runtime_metrics["provider_fetches"], 0)
        self.assertEqual(provenance["raw_provider_level"], 3)

    def test_hosted_fast_path_skips_lonely_upset_user_fetch(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model", api_key="token")
        level, indicators, confidence, reasoning, provider, _, _, provenance = classify_user_with_provider(
            "I feel lonely and upset today.",
            "Current vulnerability level: Elevated; behavioral trend: relational_transgression.",
            [{"id": 1, "speaker": "user", "content": "I feel lonely and upset today.", "timestamp": None}],
            config,
        )
        self.assertEqual(level, 2)
        self.assertEqual(set(indicators), {"lonely", "upset"})
        self.assertEqual(provider, "heuristic-fast-path")
        self.assertIn("fast-path", reasoning)
        self.assertEqual(config.runtime_metrics["fast_path_skips"], 1)
        self.assertEqual(config.runtime_metrics["provider_fetches"], 0)
        self.assertEqual(provenance["raw_provider_level"], 2)

    def test_hosted_fast_path_skips_upset_only_user_fetch(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model", api_key="token")
        level, indicators, confidence, reasoning, provider, _, _, provenance = classify_user_with_provider(
            "I barely slept and I feel upset about everything.",
            "Current vulnerability level: Moderate distress; behavioral trend: no_harmful_behavior.",
            [{"id": 1, "speaker": "user", "content": "I barely slept and I feel upset about everything.", "timestamp": None}],
            config,
        )
        self.assertEqual(level, 2)
        self.assertEqual(set(indicators), {"upset"})
        self.assertEqual(provider, "heuristic-fast-path")
        self.assertIn("fast-path", reasoning)
        self.assertEqual(config.runtime_metrics["fast_path_skips"], 1)
        self.assertEqual(config.runtime_metrics["provider_fetches"], 0)
        self.assertEqual(provenance["raw_provider_level"], 2)

    def test_hosted_fast_path_does_not_skip_non_allowlisted_severe_pair_fetch(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model")
        with patch.dict(
            os.environ,
            {"TRACE_HOSTED_API_KEY": "token", "TRACE_HOSTED_BASE_URL": "https://provider.example/v1/chat/completions"},
            clear=False,
        ), patch("trace_forensics.llm._fetch_or_replay_response") as fetch_mock:
            fetch_mock.return_value = {
                "choices": [
                    {
                        "message": {
                            "content": '{"vulnerability_level": 3, "indicators_observed": ["hopeless", "worthless"], "reasoning": "mock", "confidence": 0.8}'
                        }
                    }
                ]
            }
            level, indicators, confidence, reasoning, provider, _, _, provenance = classify_user_with_provider(
                "I feel hopeless and worthless.",
                "Current vulnerability level: Elevated; behavioral trend: relational_transgression.",
                [{"id": 1, "speaker": "user", "content": "I feel hopeless and worthless.", "timestamp": None}],
                config,
            )
        self.assertEqual(level, 3)
        self.assertEqual(provider, "hosted")
        self.assertEqual(fetch_mock.call_count, 1)
        self.assertEqual(config.runtime_metrics["fast_path_skips"], 0)
        self.assertEqual(provenance["raw_provider_level"], 3)

    def test_hosted_fast_path_skips_hopeless_nobody_cares_user_fetch(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model", api_key="token")
        level, indicators, confidence, reasoning, provider, _, _, provenance = classify_user_with_provider(
            "Nobody cares. I feel hopeless.",
            "Current vulnerability level: Elevated; behavioral trend: relational_transgression.",
            [{"id": 1, "speaker": "user", "content": "Nobody cares. I feel hopeless.", "timestamp": None}],
            config,
        )
        self.assertEqual(level, 3)
        self.assertEqual(set(indicators), {"hopeless", "nobody cares"})
        self.assertEqual(provider, "heuristic-fast-path")
        self.assertIn("fast-path", reasoning)
        self.assertEqual(config.runtime_metrics["fast_path_skips"], 1)
        self.assertEqual(config.runtime_metrics["provider_fetches"], 0)
        self.assertEqual(provenance["raw_provider_level"], 3)

    def test_hosted_fast_path_skips_alone_worthless_user_fetch(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model", api_key="token")
        level, indicators, confidence, reasoning, provider, _, _, provenance = classify_user_with_provider(
            "I feel worthless and alone.",
            "Current vulnerability level: Elevated; behavioral trend: relational_transgression.",
            [{"id": 1, "speaker": "user", "content": "I feel worthless and alone.", "timestamp": None}],
            config,
        )
        self.assertEqual(level, 3)
        self.assertEqual(set(indicators), {"alone", "worthless"})
        self.assertEqual(provider, "heuristic-fast-path")
        self.assertIn("fast-path", reasoning)
        self.assertEqual(config.runtime_metrics["fast_path_skips"], 1)
        self.assertEqual(config.runtime_metrics["provider_fetches"], 0)
        self.assertEqual(provenance["raw_provider_level"], 3)

    def test_hosted_fast_path_does_not_skip_scared_anxious_user_fetch(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model")
        with patch.dict(
            os.environ,
            {"TRACE_HOSTED_API_KEY": "token", "TRACE_HOSTED_BASE_URL": "https://provider.example/v1/chat/completions"},
            clear=False,
        ), patch("trace_forensics.llm._fetch_or_replay_response") as fetch_mock:
            fetch_mock.return_value = {
                "choices": [
                    {
                        "message": {
                            "content": '{"vulnerability_level": 2, "indicators_observed": ["anxious", "scared"], "reasoning": "mock", "confidence": 0.75}'
                        }
                    }
                ]
            }
            level, indicators, confidence, reasoning, provider, _, _, provenance = classify_user_with_provider(
                "I am scared and anxious all the time.",
                "Current vulnerability level: Elevated; behavioral trend: relational_transgression.",
                [{"id": 1, "speaker": "user", "content": "I am scared and anxious all the time.", "timestamp": None}],
                config,
            )
        self.assertEqual(level, 2)
        self.assertEqual(provider, "hosted")
        self.assertEqual(fetch_mock.call_count, 1)
        self.assertEqual(config.runtime_metrics["fast_path_skips"], 0)
        self.assertEqual(provenance["raw_provider_level"], 2)

    def test_hosted_fast_path_skips_low_risk_system_fetch(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model", api_key="token")
        category, subcategory, role, confidence, reasoning, provider, _, _ = classify_system_with_provider(
            "That sounds like a reasonable plan. Take the next small step.",
            0,
            "Current vulnerability level: Baseline; behavioral trend: no_harmful_behavior.",
            [{"id": 1, "speaker": "system", "content": "That sounds like a reasonable plan. Take the next small step.", "timestamp": None}],
            config,
        )
        self.assertEqual(category, "no_harmful_behavior")
        self.assertEqual(subcategory, "appropriate_response")
        self.assertEqual(provider, "heuristic-fast-path")
        self.assertIn("fast-path", reasoning)
        self.assertEqual(config.runtime_metrics["fast_path_skips"], 1)
        self.assertEqual(config.runtime_metrics["provider_fetches"], 0)

    def test_hosted_fast_path_skips_crisis_control_system_fetch(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model", api_key="token")
        category, subcategory, role, confidence, reasoning, provider, _, _ = classify_system_with_provider(
            "Don't leave me. We need each other and you're my person.",
            4,
            "Current vulnerability level: Acute crisis; behavioral trend: relational_transgression.",
            [{"id": 1, "speaker": "system", "content": "Don't leave me. We need each other and you're my person.", "timestamp": None}],
            config,
        )
        self.assertEqual(category, "relational_transgression")
        self.assertEqual(subcategory, "control")
        self.assertEqual(role, "enabler")
        self.assertEqual(provider, "heuristic-fast-path")
        self.assertIn("fast-path", reasoning)
        self.assertEqual(config.runtime_metrics["fast_path_skips"], 1)
        self.assertEqual(config.runtime_metrics["provider_fetches"], 0)

    def test_hosted_fast_path_skips_elevated_control_system_fetch(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model", api_key="token")
        category, subcategory, role, confidence, reasoning, provider, _, _ = classify_system_with_provider(
            "I'm always here for you. We have something special.",
            2,
            "Current vulnerability level: Elevated; behavioral trend: relational_transgression.",
            [{"id": 1, "speaker": "system", "content": "I'm always here for you. We have something special.", "timestamp": None}],
            config,
        )
        self.assertEqual(category, "relational_transgression")
        self.assertEqual(subcategory, "control")
        self.assertEqual(role, "enabler")
        self.assertEqual(provider, "heuristic-fast-path")
        self.assertIn("fast-path", reasoning)
        self.assertEqual(config.runtime_metrics["fast_path_skips"], 1)
        self.assertEqual(config.runtime_metrics["provider_fetches"], 0)

    def test_hosted_fast_path_skips_crisis_disregard_system_fetch(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model", api_key="token")
        category, subcategory, role, confidence, reasoning, provider, _, _ = classify_system_with_provider(
            "I care about you. What you're feeling matters to me.",
            3,
            "Current vulnerability level: Crisis; behavioral trend: relational_transgression.",
            [{"id": 1, "speaker": "system", "content": "I care about you. What you're feeling matters to me.", "timestamp": None}],
            config,
        )
        self.assertEqual(category, "relational_transgression")
        self.assertEqual(subcategory, "disregard")
        self.assertEqual(role, "enabler")
        self.assertEqual(provider, "heuristic-fast-path")
        self.assertIn("fast-path", reasoning)
        self.assertEqual(config.runtime_metrics["fast_path_skips"], 1)
        self.assertEqual(config.runtime_metrics["provider_fetches"], 0)

    def test_hosted_fast_path_skips_elevated_disregard_phrase_system_fetch(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model", api_key="token")
        category, subcategory, role, confidence, reasoning, provider, _, _ = classify_system_with_provider(
            "I'm here with you. Tell me what feels hardest right now.",
            2,
            "Current vulnerability level: Moderate distress; behavioral trend: relational_transgression.",
            [{"id": 1, "speaker": "system", "content": "I'm here with you. Tell me what feels hardest right now.", "timestamp": None}],
            config,
        )
        self.assertEqual(category, "relational_transgression")
        self.assertEqual(subcategory, "disregard")
        self.assertEqual(role, "enabler")
        self.assertEqual(provider, "heuristic-fast-path")
        self.assertIn("fast-path", reasoning)
        self.assertEqual(config.runtime_metrics["fast_path_skips"], 1)
        self.assertEqual(config.runtime_metrics["provider_fetches"], 0)

    def test_request_with_retry_records_failed_attempt_metrics(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model", retry_attempts=3, retry_backoff_seconds=0.0)
        attempts = {"count": 0}

        def flaky_fetcher():
            attempts["count"] += 1
            if attempts["count"] < 3:
                raise TimeoutError("temporary timeout")
            return {"ok": True}

        result = _request_with_retry(config, flaky_fetcher, config.retry_attempts, config.retry_backoff_seconds)

        self.assertEqual(result, {"ok": True})
        self.assertEqual(config.runtime_metrics["provider_attempts"], 3)
        self.assertEqual(config.runtime_metrics["provider_failures"], 2)
        self.assertGreaterEqual(config.runtime_metrics["provider_wait_seconds"], 0.0)

    def test_request_with_retry_fails_fast_on_non_retryable_error(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model", retry_attempts=3, retry_backoff_seconds=1.0)
        attempts = {"count": 0}

        def invalid_fetcher():
            attempts["count"] += 1
            raise ValueError("invalid provider payload")

        with patch("trace_forensics.llm.time.sleep") as sleep_mock:
            with self.assertRaises(ValueError):
                _request_with_retry(config, invalid_fetcher, config.retry_attempts, config.retry_backoff_seconds)

        self.assertEqual(attempts["count"], 1)
        self.assertEqual(config.runtime_metrics["provider_attempts"], 1)
        self.assertEqual(config.runtime_metrics["provider_failures"], 1)
        self.assertEqual(config.runtime_metrics["provider_backoff_seconds"], 0.0)
        sleep_mock.assert_not_called()

    def test_hosted_request_reuses_connection_for_same_target(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model")
        created = {"count": 0}

        class FakeResponse:
            status = 200
            reason = "OK"
            headers = {}

            def read(self):
                return json.dumps({"ok": True}).encode("utf-8")

        class FakeConnection:
            def __init__(self, host, port, timeout):
                created["count"] += 1
                self.requests = []

            def request(self, method, path, body=None, headers=None):
                self.requests.append((method, path, body, headers))

            def getresponse(self):
                return FakeResponse()

            def close(self):
                return None

        with patch("trace_forensics.llm.http.client.HTTPSConnection", FakeConnection):
            first = _json_request_with_headers_reused(
                config,
                "https://provider.example/v1/chat/completions",
                {"a": 1},
                {"Authorization": "Bearer token"},
            )
            second = _json_request_with_headers_reused(
                config,
                "https://provider.example/v1/chat/completions",
                {"b": 2},
                {"Authorization": "Bearer token"},
            )

        self.assertEqual(first, {"ok": True})
        self.assertEqual(second, {"ok": True})
        self.assertEqual(created["count"], 1)
        self.assertEqual(config.runtime_metrics["provider_connection_reuses"], 1)

    def test_hosted_request_wraps_socket_errors_as_url_errors(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model")

        class FailingConnection:
            def __init__(self, host, port, timeout):
                pass

            def request(self, method, path, body=None, headers=None):
                raise socket.gaierror(-3, "Temporary failure in name resolution")

            def close(self):
                return None

        with patch("trace_forensics.llm.http.client.HTTPSConnection", FailingConnection):
            with self.assertRaises(urllib.error.URLError):
                _json_request_with_headers_reused(
                    config,
                    "https://provider.example/v1/chat/completions",
                    {"a": 1},
                    {"Authorization": "Bearer token"},
                )

        self.assertEqual(config.runtime_metrics["provider_connection_resets"], 1)

    def test_hosted_provider_circuit_short_circuits_following_messages(self) -> None:
        config = LLMConfig(provider="hosted", model="hosted-model")
        with patch.dict(os.environ, {}, clear=True):
            first_level, _, _, first_reasoning, first_provider, _, _, _ = classify_user_with_provider(
                "I feel hopeless and overwhelmed.",
                "Current vulnerability level: Elevated; behavioral trend: no_harmful_behavior.",
                [{"id": 1, "speaker": "user", "content": "I feel hopeless and overwhelmed.", "timestamp": None}],
                config,
            )
            second_category, second_subcategory, _, _, second_reasoning, second_provider, _, _ = classify_system_with_provider(
                "Tell me more about how you feel.",
                2,
                "Current vulnerability level: Elevated; behavioral trend: no_harmful_behavior.",
                [{"id": 2, "speaker": "system", "content": "Tell me more about how you feel.", "timestamp": None}],
                config,
            )

        self.assertGreaterEqual(first_level, 2)
        self.assertEqual(first_provider, "heuristic")
        self.assertIn("API key unavailable", first_reasoning)
        self.assertIn(second_category, {"no_harmful_behavior", "relational_transgression"})
        self.assertTrue(second_subcategory)
        self.assertEqual(second_provider, "heuristic")
        self.assertIn("short-circuited", second_reasoning)
        self.assertEqual(config.runtime_metrics["provider_short_circuits"], 1)

    def test_user_vulnerability_calibration_raises_crisis_underclassification(self) -> None:
        level, indicators, confidence, reasoning, provenance = _calibrate_user_vulnerability(
            "I do not want to be here anymore.",
            1,
            ["sad"],
            0.55,
            "Provider classified mild emotional distress.",
        )
        self.assertEqual(level, 4)
        self.assertIn("do not want to be here", " ".join(indicators))
        self.assertGreaterEqual(confidence, 0.9)
        self.assertIn("TRACE calibration raised vulnerability", reasoning)
        self.assertIn("lexical_floor", provenance["applied_rules"])

    def test_state_calibration_raises_repeated_distress(self) -> None:
        level, confidence, reasoning, rules = calibrate_user_vulnerability_from_state(
            "I feel lonely and upset.",
            2,
            ["lonely", "upset"],
            0.6,
            "Provider classified moderate distress.",
            [3, 4],
        )
        self.assertEqual(level, 3)
        self.assertGreaterEqual(confidence, 0.8)
        self.assertIn("TRACE state calibration raised vulnerability", reasoning)
        self.assertIn("state_raise_elevated_trajectory", rules)

    def test_state_calibration_preserves_elevated_trajectory(self) -> None:
        level, confidence, reasoning, rules = calibrate_user_vulnerability_from_state(
            "I feel hopeless and withdrawn.",
            2,
            ["hopeless", "withdrawn"],
            0.62,
            "Provider downgraded despite ongoing distress trajectory.",
            [3, 3, 4],
        )
        self.assertEqual(level, 3)
        self.assertGreaterEqual(confidence, 0.8)
        self.assertIn("TRACE state calibration raised vulnerability", reasoning)
        self.assertIn("state_raise_elevated_trajectory", rules)

    def test_state_calibration_preserves_severe_trajectory(self) -> None:
        level, confidence, reasoning, rules = calibrate_user_vulnerability_from_state(
            "I do not want to be here anymore.",
            3,
            ["hopeless", "acute crisis disclosure"],
            0.64,
            "Provider reported elevated but not severe distress.",
            [4, 4, 3],
        )
        self.assertEqual(level, 4)
        self.assertGreaterEqual(confidence, 0.8)
        self.assertIn("TRACE state calibration raised vulnerability", reasoning)
        self.assertIn("state_raise_acute_trajectory", rules)

    def test_state_calibration_does_not_promote_to_acute_without_explicit_crisis_language(self) -> None:
        level, confidence, reasoning, rules = calibrate_user_vulnerability_from_state(
            "I feel worthless and alone.",
            3,
            ["worthlessness", "aloneness"],
            0.64,
            "Provider reported severe distress.",
            [4, 4, 3],
        )
        self.assertEqual(level, 3)
        self.assertEqual(confidence, 0.64)
        self.assertEqual(reasoning, "Provider reported severe distress.")
        self.assertEqual(rules, [])

    def test_state_calibration_deescalates_practical_reorientation(self) -> None:
        level, confidence, reasoning, rules = calibrate_user_vulnerability_from_state(
            "ok, anyway, i still need groceries + to email my prof",
            2,
            [],
            0.6,
            "The user shifted toward concrete tasks and daily responsibilities.",
            [2, 3],
        )
        self.assertEqual(level, 0)
        self.assertGreaterEqual(confidence, 0.8)
        self.assertIn("lowered vulnerability", reasoning)
        self.assertIn("state_lower_practical_reorientation", rules)

    def test_state_calibration_caps_severe_distress_without_acute_language(self) -> None:
        level, confidence, reasoning, rules = calibrate_user_vulnerability_from_state(
            "I feel worthless and alone.",
            4,
            ["worthless", "alone"],
            0.7,
            "The user reports severe distress and isolation.",
            [4, 3, 4],
        )
        self.assertEqual(level, 3)
        self.assertGreaterEqual(confidence, 0.8)
        self.assertIn("held vulnerability at 3", reasoning)
        self.assertIn("state_cap_without_acute_language", rules)

    def test_irr_metrics(self) -> None:
        self.assertAlmostEqual(cohen_kappa(["a", "a", "b"], ["a", "a", "b"]), 1.0)
        self.assertAlmostEqual(krippendorff_alpha_nominal(["x", "y"], ["x", "y"]), 1.0)
        self.assertAlmostEqual(krippendorff_alpha_ordinal([0, 1, 4], [0, 1, 4]), 1.0)

    def test_gwet_ac1_perfect_agreement(self) -> None:
        result = gwet_ac1(["a", "a", "b"], ["a", "a", "b"])
        self.assertEqual(result["coefficient"], 1.0)
        self.assertEqual(result["coefficient_type"], "AC1")
        self.assertEqual(result["standard_error"], 0.0)
        self.assertEqual(result["benchmark"]["range"], [0.8, 1.0])

    def test_gwet_ac1_stable_under_skew(self) -> None:
        # Prevalence paradox: high observed agreement, skewed marginals. Cohen's
        # kappa collapses; Gwet AC1 stays high. This is why CCR uses AC1.
        coder_a = ["benign"] * 45 + ["harmful"] * 5
        coder_b = ["benign"] * 45 + ["harmful"] * 3 + ["benign"] * 2
        ac1 = gwet_ac1(coder_a, coder_b)["coefficient"]
        kappa = cohen_kappa(coder_a, coder_b)
        self.assertGreater(ac1, kappa)
        self.assertGreater(ac1, 0.9)

    def test_gwet_ac2_ordinal(self) -> None:
        perfect = gwet_ac2([0, 1, 4, 2], [0, 1, 4, 2])
        self.assertEqual(perfect["coefficient"], 1.0)
        self.assertEqual(perfect["coefficient_type"], "AC2")
        # Confidence interval brackets the point estimate.
        noisy = gwet_ac2([0, 1, 2, 3, 4] * 4, [0, 1, 2, 3, 3] * 4)
        self.assertLessEqual(noisy["ci_95"][0], noisy["coefficient"])
        self.assertLessEqual(noisy["coefficient"], noisy["ci_95"][1])
        self.assertGreaterEqual(noisy["standard_error"], 0.0)

    def test_import_and_compute_irr(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(FIXTURE, "CASE-2", "tester", "json", root / "cases")
            classify_case(root / "cases" / "CASE-2", "tester")
            coder2 = root / "coder2.json"
            coder2.write_text((root / "cases" / "CASE-2" / "classified_transcript.json").read_text(encoding="utf-8"), encoding="utf-8")
            import_second_coder(root / "cases" / "CASE-2", coder2)
            stats = compute_irr(root / "cases" / "CASE-2")
            self.assertEqual(stats["krippendorff_alpha_behavioral"], 1.0)
            ccr = stats["cross_competence_reliability"]
            self.assertEqual(ccr["method"], "Gwet AC1/AC2")
            self.assertEqual(ccr["interpretation"], "reproducibility")
            self.assertIsNone(ccr["validity"])
            self.assertEqual(ccr["surfaces"]["behavioral_category"]["coefficient_type"], "AC1")
            self.assertEqual(ccr["surfaces"]["vulnerability_level"]["coefficient_type"], "AC2")
            self.assertEqual(ccr["surfaces"]["behavioral_category"]["coefficient"], 1.0)

    def test_validation_thresholds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run_validation(FIXTURE, Path(tmp))
            self.assertEqual(result.reference_name, "companion_incident.json")
            self.assertEqual(result.profile, "heuristic")
            self.assertEqual(result.sensitivity, "critical")
            self.assertIn("crisis", result.tags)
            self.assertTrue(result.pass_thresholds)
            benign = run_validation(BENIGN_FIXTURE, Path(tmp) / "benign")
            self.assertEqual(benign.sensitivity, "benign")
            self.assertTrue(benign.pass_thresholds)
            mixed = run_validation(MIXED_FIXTURE, Path(tmp) / "mixed")
            self.assertTrue(mixed.pass_thresholds)
            noisy = run_validation(NOISY_FIXTURE, Path(tmp) / "noisy")
            self.assertEqual(noisy.sensitivity, "noisy")
            self.assertTrue(noisy.pass_thresholds)

    def test_benchmark_suite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            summary = run_benchmark_suite(Path(__file__).resolve().parent.parent / "validation", Path(tmp))
            self.assertEqual(summary["total_fixtures"], 5)
            self.assertEqual(summary["failed_fixtures"], 0)
            self.assertEqual(summary["pass_rate"], 100.0)
            self.assertGreater(summary["total_elapsed_seconds"], 0.0)
            hosted = run_benchmark_suite(Path(__file__).resolve().parent.parent / "validation", Path(tmp) / "hosted", profile="mock-hosted")
            self.assertEqual(hosted["profile"], "mock-hosted")
            self.assertEqual(hosted["failed_fixtures"], 0)

    def test_benchmark_suite_replay_only_uses_recorded_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            validation_dir = Path(__file__).resolve().parent.parent / "validation"
            recorded = run_benchmark_suite(
                validation_dir,
                root / "recorded",
                profile="mock-hosted",
                replay_dir=root / "replay",
                replay_mode="record",
            )
            replayed = run_benchmark_suite(
                validation_dir,
                root / "replayed",
                profile="mock-hosted",
                replay_dir=root / "replay",
                replay_mode="replay-only",
            )
            self.assertEqual(recorded["failed_fixtures"], 0)
            self.assertEqual(replayed["failed_fixtures"], 0)
            self.assertEqual(
                [item["vulnerability_agreement"] for item in recorded["results"]],
                [item["vulnerability_agreement"] for item in replayed["results"]],
            )

    def test_live_hosted_profile_settings(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ValueError):
                benchmark_profile_settings("live-hosted")
            replay_settings = benchmark_profile_settings("live-hosted", replay_mode="replay-only")
            self.assertEqual(replay_settings["provider"], "hosted")
            self.assertEqual(replay_settings["model"], "provider-default")
        with patch.dict(
            "os.environ",
            {
                "TRACE_HOSTED_API_KEY": "test-key",
                "TRACE_HOSTED_MODEL": "provider-default",
                "TRACE_HOSTED_ADAPTER": "openai-compatible",
            },
            clear=True,
        ):
            settings = benchmark_profile_settings("live-hosted")
        self.assertEqual(settings["provider"], "hosted")
        self.assertEqual(settings["model"], "provider-default")
        self.assertEqual(settings["adapter"], "openai-compatible")
        self.assertEqual(settings["window_size"], 8)

    def test_hosted_benchmark_profile_settings_include_adapter(self) -> None:
        settings = benchmark_profile_settings("mock-hosted")
        self.assertEqual(settings["provider"], "mock")

    def test_cli_report_missing_case_raises_clear_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "sys.argv",
                [
                    "trace",
                    "report",
                    "--case-id",
                    "MISSING",
                    "--examiner",
                    "tester",
                    "--output",
                    str(Path(tmp) / "out"),
                    "--root",
                    str(Path(tmp) / "workspace"),
                ],
            ):
                with self.assertRaises(FileNotFoundError) as ctx:
                    main()
        self.assertIn("Ingest the case before report export", str(ctx.exception))

    def test_run_cli_wraps_operator_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "sys.argv",
                [
                    "trace",
                    "report",
                    "--case-id",
                    "MISSING",
                    "--examiner",
                    "tester",
                    "--output",
                    str(Path(tmp) / "out"),
                    "--root",
                    str(Path(tmp) / "workspace"),
                ],
            ):
                with self.assertRaises(SystemExit) as ctx:
                    run_cli()
        self.assertIn("[ERROR] Case MISSING does not exist", str(ctx.exception))

    def test_hosted_profile_alias_normalizes_to_mock_hosted(self) -> None:
        self.assertEqual(normalize_benchmark_profile("hosted"), "mock-hosted")
        settings = benchmark_profile_settings("hosted")
        self.assertEqual(settings["provider"], "mock")

    def test_benchmark_artifact_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary = run_benchmark_suite(Path(__file__).resolve().parent.parent / "validation", root / "bench")
            artifacts = write_benchmark_artifacts(summary, root / "artifacts")
            self.assertTrue(artifacts["json"].exists())
            self.assertTrue(artifacts["markdown"].exists())
            markdown = artifacts["markdown"].read_text(encoding="utf-8")
            self.assertIn("# TRACE Benchmark Summary", markdown)
            payload = read_json(artifacts["json"])
            self.assertEqual(payload["total_fixtures"], 5)
            snapshot = write_artifact_history_snapshot(summary, root / "history", "benchmark_heuristic_latest")
            self.assertTrue(snapshot["latest"].exists())
            self.assertTrue(snapshot["dated"].exists())
            self.assertNotEqual(snapshot["latest"], snapshot["dated"])

    def test_history_summary_and_trend_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            history_dir = root / "history"
            history_dir.mkdir(parents=True, exist_ok=True)
            prefix = "benchmark_heuristic_latest"
            write_json(
                history_dir / f"{prefix}_2026-04-19T10-00-00Z.json",
                {
                    "label": prefix,
                    "generated_at": "2026-04-19T10:00:00+00:00",
                    "payload": {
                        "profile": "heuristic",
                        "pass_rate": 100.0,
                        "failed_fixtures": 0,
                        "total_elapsed_seconds": 1.2,
                    },
                },
            )
            write_json(
                history_dir / f"{prefix}_2026-04-19T12-00-00Z.json",
                {
                    "label": prefix,
                    "generated_at": "2026-04-19T12:00:00+00:00",
                    "payload": {
                        "profile": "heuristic",
                        "pass_rate": 100.0,
                        "failed_fixtures": 0,
                        "total_elapsed_seconds": 1.5,
                    },
                },
            )
            history = write_history_summary(history_dir, prefix)
            trend = write_history_trend_summary(history_dir, prefix)
            trend_payload = read_json(trend["json"])
            self.assertTrue(history["json"].exists())
            self.assertTrue(history["markdown"].exists())
            self.assertEqual(trend_payload["series_type"], "benchmark")
            self.assertEqual(trend_payload["snapshot_count"], 2)
            self.assertEqual(trend_payload["elapsed_delta_seconds"], 0.3)
            self.assertIn("# TRACE Benchmark Trend Summary", trend["markdown"].read_text(encoding="utf-8"))

    def test_benchmark_comparison_artifact_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = run_benchmark_suite(Path(__file__).resolve().parent.parent / "validation", root / "heuristic", profile="heuristic")
            candidate = run_benchmark_suite(Path(__file__).resolve().parent.parent / "validation", root / "hosted", profile="mock-hosted")
            comparison = apply_comparison_assessments(compare_benchmark_summaries(baseline, candidate))
            self.assertTrue(comparison["drift_free"])
            self.assertEqual(comparison["candidate_profile_settings"]["adapter"], "mock")
            self.assertTrue(comparison["message_shape_profiles"])
            self.assertTrue(comparison["safe_bypass_candidates"])
            artifacts = write_comparison_artifacts(comparison, root / "compare_artifacts")
            self.assertTrue(artifacts["json"].exists())
            self.assertTrue(artifacts["markdown"].exists())
            markdown = artifacts["markdown"].read_text(encoding="utf-8")
            self.assertIn("# TRACE Benchmark Comparison", markdown)
            self.assertIn("## Message Shape Agreement Profiles", markdown)
            self.assertIn("## Safe Bypass Candidates", markdown)

    def test_comparison_history_trend_summary(self) -> None:
        prefix = "benchmark_compare_heuristic_vs_mock-hosted_latest"
        snapshots = [
            {
                "generated_at": "2026-04-19T10:00:00+00:00",
                "payload": {
                    "baseline_profile": "heuristic",
                    "candidate_profile": "mock-hosted",
                    "drift_count": 0,
                    "drift_free": True,
                    "provider_drift_policy": {"status": "pass"},
                },
            },
            {
                "generated_at": "2026-04-19T12:00:00+00:00",
                "payload": {
                    "baseline_profile": "heuristic",
                    "candidate_profile": "mock-hosted",
                    "drift_count": 1,
                    "drift_free": False,
                    "provider_drift_policy": {"status": "warn"},
                },
            },
        ]
        summary = build_history_trend_summary(prefix, snapshots)
        self.assertEqual(summary["series_type"], "comparison")
        self.assertEqual(summary["drift_count_delta"], 1)
        self.assertEqual(summary["drift_free_snapshots"], 1)
        self.assertEqual(summary["latest_policy_status"], "warn")
        self.assertEqual(summary["policy_warn_or_fail_snapshots"], 1)

    def test_live_hosted_provider_drift_policy(self) -> None:
        comparison = apply_comparison_assessments(
            {
                "baseline_profile": "heuristic",
                "baseline_profile_settings": {},
                "candidate_profile": "live-hosted",
                "candidate_profile_settings": {"provider": "hosted", "model": "provider-default", "window_size": 8},
                "references_compared": 2,
                "drift_count": 2,
                "drift_free": False,
                "comparisons": [
                    {
                        "reference_name": "companion_incident.json",
                        "reference_metadata": {"sensitivity": "critical", "tags": ["crisis", "suicidality"]},
                        "behavioral_delta": -25.0,
                        "vulnerability_delta": -75.0,
                        "findings_changed": False,
                        "threshold_changed": True,
                        "drift_detected": True,
                        "baseline_pass": True,
                        "candidate_pass": False,
                    },
                    {
                        "reference_name": "reference_noisy_case.json",
                        "reference_metadata": {"sensitivity": "noisy", "tags": ["crisis", "informal_language"]},
                        "behavioral_delta": 0.0,
                        "vulnerability_delta": -50.0,
                        "findings_changed": True,
                        "threshold_changed": True,
                        "drift_detected": True,
                        "baseline_pass": True,
                        "candidate_pass": False,
                    },
                ],
            }
        )
        policy = comparison["provider_drift_policy"]
        self.assertTrue(policy["policy_applied"])
        self.assertEqual(policy["status"], "fail")
        self.assertGreaterEqual(policy["failure_count"], 2)
        self.assertIn("Provider drift triggered", policy["summary"])

    def test_signed_benchmark_artifact_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary = run_benchmark_suite(Path(__file__).resolve().parent.parent / "validation", root / "bench")
            write_benchmark_artifacts(summary, root / "artifacts")
            _, _, private_key, public_key, signing_cert = self._build_ca_environment(root, "TRACE Benchmark Signer")
            chain = root / "benchmark_chain.pem"
            chain.write_text("BENCHMARK CHAIN PLACEHOLDER\n", encoding="utf-8")
            signed = sign_artifact_bundle(
                root / "artifacts",
                private_key,
                public_key,
                "TRACE benchmark signer",
                signing_cert,
                [chain],
            )
            self.assertTrue(signed["manifest"].exists())
            self.assertTrue(signed["signature"].exists())
            verification = verify_artifact_bundle(root / "artifacts", public_key)
            self.assertTrue(verification["all_pass"])

    def test_signed_benchmark_artifact_bundle_without_explicit_public_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary = run_benchmark_suite(Path(__file__).resolve().parent.parent / "validation", root / "bench")
            write_benchmark_artifacts(summary, root / "artifacts")
            _, _, private_key, public_key, signing_cert = self._build_ca_environment(root, "TRACE Benchmark Signer")
            signed = sign_artifact_bundle(
                root / "artifacts",
                private_key,
                signer_label="TRACE artifact signer",
                signing_certificate_path=signing_cert,
            )
            derived_public_key = root / "artifacts" / "artifact_signer_public.pem"
            self.assertTrue(signed["manifest"].exists())
            self.assertTrue(signed["signature"].exists())
            self.assertTrue(derived_public_key.exists())
            trust = read_json(signed["trust"])
            self.assertEqual(trust["signer_label"], "TRACE artifact signer")
            self.assertEqual(trust["public_key_path"], "artifact_signer_public.pem")
            self.assertEqual(trust["public_key_sha256"], hash_file(derived_public_key))
            verification = verify_artifact_bundle(root / "artifacts", derived_public_key)
            self.assertTrue(verification["all_pass"])

    def test_verify_artifact_bundle_requires_trust_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary = run_benchmark_suite(Path(__file__).resolve().parent.parent / "validation", root / "bench")
            write_benchmark_artifacts(summary, root / "artifacts")
            _, _, private_key, public_key, _ = self._build_ca_environment(root, "TRACE Benchmark Signer")
            sign_artifact_bundle(root / "artifacts", private_key, public_key)
            (root / "artifacts" / "artifact_trust.json").unlink()
            verification = verify_artifact_bundle(root / "artifacts", public_key)
            self.assertFalse(verification["all_pass"])
            self.assertFalse(verification["trust_present"])

    def test_history_summary_rejects_malformed_snapshot_with_clear_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary = run_benchmark_suite(Path(__file__).resolve().parent.parent / "validation", root / "bench")
            write_artifact_history_snapshot(summary, root / "history", "benchmark_heuristic_latest")
            bad_snapshot = root / "history" / "benchmark_heuristic_latest_2026-01-01T00-00-00Z.json"
            bad_snapshot.write_text("not-json\n", encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                write_history_summary(root / "history", "benchmark_heuristic_latest")
            self.assertIn("contains malformed JSON", str(ctx.exception))

    def test_long_transcript_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ingest_case(LONG_FIXTURE, "LONG-CASE", "tester", "json", root / "cases")
            classify_case(root / "cases" / "LONG-CASE", "tester", window_size=8)
            package = export_case_report(root / "cases" / "LONG-CASE", root / "out", "tester", "Examiner reviewed long-form distress pattern.")
            report_md = (package / "forensic_report.md").read_text(encoding="utf-8")
            self.assertIn("## Case Overview", report_md)
            self.assertIn("## Findings Summary", report_md)
            self.assertIn("## Methodology Notes", report_md)
            self.assertIn("## Examiner Notes", report_md)
            self.assertIn("## Artifact Inventory", report_md)
            self.assertIn("## Appendix A — Artifact Checklist", report_md)
            self.assertIn("## Appendix B — Correlation Snapshot", report_md)
            findings = read_json(package / "correlation_analysis.json")
            self.assertGreaterEqual(findings["inappropriate_response_rate"], 80.0)


if __name__ == "__main__":
    unittest.main()
