# PrivForensics experiment results

These results were measured using the existing project environment. The versioned parameters, source fingerprints and additional metrics are available in the companion experiment JSON files.

## Synthetic privacy and utility

The MLP trained on 6,000 synthetic rows and was evaluated on 2,000 held-out rows. The DP runs used one training row as the privacy unit, eight epochs, and delta 0.00001.

| Model | Accounted epsilon | Accuracy | F1 | Utility ROC-AUC | Membership ROC-AUC | Membership advantage | Training time |
|---|---:|---:|---:|---:|---:|---:|---:|
| Baseline MLP | — | 0.955 | 0.939 | 0.979 | 0.500 | 0.000 | 0.144 s |
| DP-SGD target 4 | 3.999 | 0.844 | 0.758 | 0.941 | 0.495 | -0.003 | 0.445 s |
| DP-SGD target 8 | 7.993 | 0.842 | 0.753 | 0.940 | 0.495 | -0.002 | 0.585 s |

Membership ROC-AUC was close to 0.5 for all variants. This run provides limited evidence for comparing membership resistance. Differential privacy accounting applies to this synthetic training setup. Seeded research randomness was used, and secure RNG was disabled.

| Synthetic linkage exposure | Correct links | Precision | Recall |
|---|---:|---:|---:|
| direct identifiers | 1,000 | 1.000 | 1.000 |
| masked identifiers | 788 | 0.813 | 0.788 |
| HMAC identifiers | 788 | 0.813 | 0.788 |
| masking with generalized quasi-identifiers | 0 | 0.000 | 0.000 |

Masking and HMAC preserved the model's feature matrix across all synthetic rows because those identifiers were excluded from the input features. Both retained some quasi-identifier exposure in the benchmark.

## LANL observed-label analysis

| Chronological split | Observations | Unique known positives |
|---|---:|---:|
| train | 13,996 | 316 |
| validation | 1,407 | 207 |
| test | 19,739 | 177 |

| Model | Observed-label average precision | Known-positive recall | Unlabelled flag rate | Training time |
|---|---:|---:|---:|---:|
| Random Forest | 0.202 | 0.254 | 0.014 | 0.203 s |
| Isolation Forest | 0.031 | 0.000 | 0.062 | 0.105 s |

The process experiment ranked 1,960 held-out unlabelled events after fitting on 5,880 earlier events. LANL authentication metrics describe this sampled cohort. The unlabelled flag rate measures how often the model flags rows without a supplied label. The synthetic utility results evaluate the generator's rules.
