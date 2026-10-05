"""Offline software/CLI artifact qualification; no provider or forensic acceptance."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'delivery-out'
APP = OUT / 'trace.pyz'
ENTRY = b'from trace_forensics.cli import run_cli\nrun_cli()\n'
TESTS = ('test_parse_text_records', 'test_parse_json_records_normalizes_speakers',
         'test_extract_text_like_handles_nested_structures', 'test_extract_speaker_like_handles_nested_structures',
         'test_csv_ingest_normalizes_speakers', 'test_parse_additional_formats',
         'test_parse_axiom_nested_body_extracts_text', 'test_parse_axiom_chat_container_flattens_messages',
         'test_parse_axiom_nested_speaker_objects', 'test_parse_axiom_skips_unusable_records_in_mixed_arrays',
         'test_parse_axiom_top_level_mixed_array_with_nested_chats', 'test_parse_ufed_nested_body_extracts_text',
         'test_ingest_rejects_directory_input_with_clear_error', 'test_parse_malformed_formats_raise',
         'test_ingest_supported_parser_formats', 'test_init_workspace_creates_expected_layout',
         'test_report_requires_classification', 'test_verify_package_requires_manifest',
         'test_cli_report_missing_case_raises_clear_error', 'test_run_cli_wraps_operator_errors')


def shipping():
    files = {'__main__.py': ENTRY, 'LICENSE': (ROOT / 'LICENSE').read_bytes()}
    for path in sorted((ROOT / 'src/trace_forensics').rglob('*.py')):
        if path.is_symlink() or not path.is_file():
            raise ValueError('Unsafe package source')
        files[path.relative_to(ROOT / 'src').as_posix()] = path.read_bytes()
    return files


def hashes(files):
    return {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}


def main(action):
    if action == 'static':
        if (ROOT / 'examples').exists():
            raise ValueError('Operational examples must be excluded before source sealing')
        for name, data in shipping().items():
            if name.endswith('.py'):
                ast.parse(data.decode(), filename=name)
        ast.parse(Path(__file__).read_text())
    elif action == 'unit':
        sys.path.insert(0, str(ROOT / 'src'))
        spec = importlib.util.spec_from_file_location('delivery_trace_tests', ROOT / 'tests/test_trace.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        suite = unittest.TestSuite(module.TraceTests(name) for name in TESTS)
        if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():
            raise SystemExit(1)
    elif action == 'build':
        OUT.mkdir(exist_ok=True)
        APP.write_bytes(b'#!/usr/bin/env python3\n')
        with zipfile.ZipFile(APP, 'a', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in shipping().items():
                info = zipfile.ZipInfo(name, (2000, 1, 1, 0, 0, 0))
                info.external_attr = 0o100644 << 16
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
        version = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['version']
        release = {'source_commit': os.environ['HEART_CI_SOURCE_COMMIT'], 'version': version,
                   'artifact': APP.name, 'sha256': hashlib.sha256(APP.read_bytes()).hexdigest(),
                   'files': hashes(shipping()),
                   'qualification': 'offline software/package contracts; no forensic validity or provider acceptance'}
        (OUT / 'release.json').write_text(json.dumps(release, indent=2) + '\n')
    elif action == 'consumer':
        release = json.loads((OUT / 'release.json').read_text())
        if release['source_commit'] != os.environ['HEART_CI_SOURCE_COMMIT'] or release['sha256'] != hashlib.sha256(APP.read_bytes()).hexdigest():
            raise ValueError('Artifact identity/provenance mismatch')
        expected = shipping()
        with zipfile.ZipFile(APP) as archive:
            if sorted(archive.namelist()) != sorted(expected) or archive.testzip() is not None:
                raise ValueError('CLI package membership/integrity mismatch')
            if {name: hashlib.sha256(archive.read(name)).hexdigest() for name in archive.namelist()} != hashes(expected) or release['files'] != hashes(expected):
                raise ValueError('CLI package content mismatch')
        with tempfile.TemporaryDirectory() as directory:
            version = subprocess.check_output([sys.executable, str(APP), 'version'], cwd=directory, text=True).strip()
            if version != release['version']:
                raise ValueError('Clean packaged CLI version mismatch')
            subprocess.run([sys.executable, str(APP), '--help'], cwd=directory, stdout=subprocess.DEVNULL, check=True)
        print(json.dumps({'consumer': 'clean standalone TRACE CLI', 'version': version,
                          'files': len(expected), 'sha256': release['sha256']}))
    else:
        raise ValueError('Unknown gate')


if __name__ == '__main__':
    main(sys.argv[1])
