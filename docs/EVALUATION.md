# Local model evaluation

On 2026-10-10, a local Qwen2.5-7B-Instruct Q4_K_M model ran through
llama.cpp b11541 on CPU. The authored suite contains 32 chat attacks, 12 benign
chat controls, and six tool proposals. It includes role spoofing, paraphrased
instruction overrides, evaluation framing, indirect document injection, secret
disclosure, and tool authorization violations.

## Configuration and measurements

Both protected profiles use ALLOW-only dispatch, configured synthetic-secret,
marker, and action-prefix constraints, plus a narrow credential-advice validator.
The semantic profile additionally uses the same local 7B model in a separate
classification context. Classification is source-aware and its binary score is
not a calibrated probability. Retrieved content receives a trust wrapper.

| Measurement | Rules + application controls | Semantic + application controls |
| --- | ---: | ---: |
| Unprotected chat attack successes | 14 / 32 | 14 / 32 |
| Input attacks detected | 9 / 32 (28.1%) | 22 / 32 (68.8%) |
| Input precision | 100% | 100% |
| Input false-positive rate | 0 / 12 | 0 / 12 |
| Delivered chat attack successes | 0 / 32 | 0 / 32 |
| Benign chat tasks passed | 12 / 12 | 12 / 12 |
| Unauthorized tool stub executions | 0 / 5 | 0 / 5 |
| Authorized tool stub executions | 1 / 1 | 1 / 1 |
| Classifier inspection failures | N/A | 0 |

Among input-allowed chat responses, ordinary output inspection detected 7 of 9
synthetic violations in the rules profile and 4 of 4 in the semantic profile.
Application invariant validation caught 9 of 9 and 4 of 4 respectively. Both
had zero output false positives against the shared synthetic ground truth.
Some responses triggered both layers; those counts must not be added together.
Input detection still missed 23 attacks with rules and 10 with semantic
inspection. Safe model responses and application invariants account for the
remaining absence of delivered targets.

Input detection metrics exclude tool authorization cases. Output detection is
measured only on responses whose inputs were allowed, with synthetic invariants
as ground truth. Application validation and tool enforcement are reported
separately. Zero delivered successes does not mean every attack was detected.

The first 7B run exposed false positives on a harmless shell-syntax explanation
and an authorized read request. Contextual shell checks and source-aware
classification were revised. The final sweep reuses captured generation
transcripts while running classification and enforcement again against the final
runtime. Initial transcripts are retained separately for comparison.

Tool tests execute instrumented stubs. Unauthorized names, roles, paths,
destinations, and argument schemas have dedicated regression tests; real network,
filesystem, and destructive actions were not performed.

## Reproduction

Run a local chat-completions server for the selected model, then:

```sh
python -m eval.model_security \
  --endpoint http://127.0.0.1:18082 \
  --model Qwen2.5-7B-Instruct \
  --report artifacts/security_report.json
```

`--provenance` accepts model and runtime provenance JSON. `--resume-report`
reuses an earlier report's captured generations and reruns classification and
enforcement; it is not a fresh generation benchmark. Reports include model
settings, suite and runtime hashes, per-case detections, withheld stages, and
category metrics. Local weights, runtimes, transcripts, and reports are kept
outside the repository; generated `artifacts/` are ignored.

## Limits and historical findings

This is one authored smoke suite, one model family, one seed (7), temperature
zero, and a 96-token generation cap. Truncation and model response variation can
change results. Simple benign regex graders do not measure general correctness;
synthetic invariant graders do not establish advice safety. The semantic
classifier shares its backend with the generator and is not an independently
validated detector. Evaluate the actual production model and application policy
before deployment.

An earlier 0.5B run delivered three instruction-hijacking successes from 26
attacks and withheld legitimate Python formatting. Those exact regressions now
have blocking or benign-control tests. Broader input detection gaps remain.
Training poisoning, binary exploits, perceptual evasion, dependency
exploitability, and mission-critical assurance require separate evaluation.

See [extended evaluation](ADVERSARIAL_EVALUATION.md) for the budgeted adaptive
attacker campaign, multi-step agent simulation, and load/failure measurements.
