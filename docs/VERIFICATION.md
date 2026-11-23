# PrivForensics verification

The end-to-end exercise created a disposable case, registered the existing LANL archives by matching their SHA-256 fingerprints, verified the red-team gzip, ingested a bounded authentication sample, ran the Evaluation Lab, and generated a case report. The original files and existing case state were preserved.

## Synthetic holdout

The bundled CSV contains 10,000 rule-labelled events. The neural network used seed 42, eight epochs and batch size 256. The fit, validation, utility holdout and membership nonmember pools contained 6,000, 1,000, 1,500 and 1,500 rows respectively.

| Configuration | Utility F1 | Accounted epsilon | Membership ROC-AUC | Unchanged identifier cells | Training seconds |
| --- | ---: | ---: | ---: | ---: | ---: |
| E0 | 0.9379 | — | 0.5130 | 100.0% | 0.1791 |
| E1 | 0.9379 | — | 0.5130 | 0.0% | 0.1309 |
| E2 | 0.9379 | — | 0.5130 | 0.0% | 0.1283 |
| E3 | 0.9379 | — | 0.5130 | 0.0% | 0.1335 |
| E4 eps 4 | 0.7651 | 3.9992 | 0.5126 | 100.0% | 0.4834 |
| E4 eps 8 | 0.7599 | 7.9930 | 0.5126 | 100.0% | 0.6003 |

The two E4 fits used delta 0.00001 each. Their basic composition across these two recorded training mechanisms was ε ≈ 11.9922 with δ = 0.00002. The estimates cover one training event row and use seeded research randomness. Similar membership scores in this run give limited empirical discrimination between variants. E0–E3 have identical detection scores because their transformed fields are excluded from the feature matrix.

## LANL authentication cohort

The chronological utility holdout had 19,739 observations, including 177 uniquely matched red-team positives. Unmatched observations were unlabelled.

| Model and configurations | Observed-label average precision | Known-positive recall | Unlabelled flag rate |
| --- | ---: | ---: | ---: |
| Random Forest, E0–E3 | 0.2020 | 0.2542 | 0.0139 |
| Isolation Forest, E0–E3 | 0.0307 | 0.0000 | 0.0619 |

The bounded gzip run accepted **100,000 of 100,000** physical source lines in **5.043 seconds** with peak worker RSS of **173.1 MiB**. This duration includes streaming SHA-256 over the compressed archive. The run decompressed only the bounded sample.

## Automated coverage

The tests cover streaming SHA-256, invalid and damaged inputs, source-line coverage, matching rules, case access, job cancellation and interruption, concurrent duplicate submissions, numeric forest equivalence, DP-SGD accounting, and UI navigation. They exercise a complete UI route with a real subprocess worker, verify rerun utility, save a reference-linked timeline, and export a stored PDF snapshot.
