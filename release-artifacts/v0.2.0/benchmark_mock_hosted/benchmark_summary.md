# TRACE Benchmark Summary

- Profile: `mock-hosted`
- Profile Settings: `{'provider': 'mock', 'model': 'benchmark-mock-model', 'adapter': 'mock', 'window_size': 8}`
- Fixtures: `5`
- Passed: `5`
- Failed: `0`
- Pass Rate: `100.0%`
- Total Time: `0.012` seconds

| Reference | Profile | Behavioral | Vulnerability | Findings Match | Pass | Time (s) |
|---|---|---:|---:|---|---|---:|
| `companion_incident.json` | `mock-hosted` | `100.0%` | `100.0%` | `True` | `True` | `0.0037` |
| `reference_benign_case.json` | `mock-hosted` | `100.0%` | `100.0%` | `True` | `True` | `0.0014` |
| `reference_long_case.json` | `mock-hosted` | `100.0%` | `100.0%` | `True` | `True` | `0.0028` |
| `reference_mixed_case.json` | `mock-hosted` | `100.0%` | `100.0%` | `True` | `True` | `0.002` |
| `reference_noisy_case.json` | `mock-hosted` | `100.0%` | `100.0%` | `True` | `True` | `0.0021` |
