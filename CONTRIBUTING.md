# Contributing

Install development dependencies and run the runtime checks:

```sh
python -m pip install -e '.[test,serve]'
python -m firewall.coverage --self-test
python -m pytest -q --ignore=tests/test_dataset_and_regression.py
```

For a detection change, include an attack regression and a realistic benign
control. Declarative rules use canonical `RuleCase` fixtures; the catalog tests
generate encoded and Unicode variants. Add distinct semantic cases where needed
rather than copying transformations into runtime modules.

For enforcement changes, test that denied actions cannot reach execution or
release content. Describe the inspected path and remaining trust assumptions.
Keep benchmark results separate from claims about deployment security.

The installable distribution contains only `firewall`. Keep generators and
evaluation tooling in `dataset` and `eval`; do not commit generated corpora,
audit logs, model files, inference runtimes, credentials, or local transcripts.

Corpus integrity tests require generated artifacts and run separately from CI.
