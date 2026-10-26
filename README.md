# SPECTRA M4 — AI Risk Engine

## What changed

This version fixes the prototype risk-calibration problem and separates
synthetic demonstration results from real-dataset evaluation.

### 1. Held-out percentile calibration

The Isolation Forest is trained on normal traffic only. The normal data is
split into a training portion and a held-out calibration portion.

For a new observation:

```text
Isolation Forest decision_function
        |
        v
negative score = anomaly score
        |
        v
empirical percentile vs held-out normal scores
        |
        v
risk score in [0, 1]
```

Interpretation:

- `0.97` = more anomalous than approximately 97% of the held-out normal reference traffic.
- `risk < 0.97` → `ALLOW`
- `0.97 <= risk < 0.995` → `MFA / MONITOR`
- `risk >= 0.995` → `DROP`

These are prototype engineering thresholds, not universal security standards.

### 2. No duplicate risk logic

`risk_engine.py` now calls `m4_interface.py` instead of maintaining a second
implementation.

### 3. Robust paths

Model and calibration files are resolved relative to the M4 project directory,
so commands do not depend on the current working directory.

### 4. Inference timing

The interface calls `decision_function()` once and reports inference latency.
The exact latency depends on the machine and should be measured on the machine
used for the review.

### 5. Evaluation

`evaluate_model.py` is explicitly a **synthetic sanity test**. It reports:

- Precision
- Recall
- F1-score
- ROC-AUC
- False-positive rate
- Median/P95 inference latency

It must not be presented as real-world detection performance.

`evaluate_unsw_nb15.py` evaluates the same four-feature M4 design on UNSW-NB15
when the official CSV files are placed under `data/`.

The mapping is:

| M4 feature | UNSW-NB15 field |
|---|---|
| `packet_size` | `smean` |
| `request_rate` | `rate` |
| `connection_count` | `ct_srv_src` |
| `inter_arrival_time` | `sinpkt / 1000` |

Training remains unsupervised: only `label == 0` rows from the UNSW training
file are used to fit the Isolation Forest. A held-out normal split is used for
risk calibration.

## Run

Install dependencies:

```bash
pip install numpy pandas scikit-learn matplotlib joblib
```

From the M4 project root:

```bash
python src/generate_dataset.py
python src/train_model.py
python src/demo.py
python src/evaluate_model.py
python src/test_model.py
```

For UNSW-NB15, place:

```text
data/UNSW_NB15_training-set.csv
data/UNSW_NB15_testing-set.csv
```

then run:

```bash
python src/evaluate_unsw_nb15.py
python src/visualize_unsw_nb15.py
```

## Real UNSW-NB15 Baseline Evaluation

Evaluated on 82,332 test samples (37,000 normal, 45,332 attack):

| Metric | Real UNSW-NB15 Baseline | Synthetic Sanity Test |
|---|---|---|
| Precision | **83.12%** | 76.92% |
| Recall | **17.78%** | 100.00% |
| F1-score | **29.29%** | 86.96% |
| False-Positive Rate | **4.42%** | 7.50% |
| ROC-AUC | **0.7570** | 1.0000 |
| Median Latency | **5.720 ms** | 6.242 ms |
| P95 Latency | **8.439 ms** | — |

Generated artifacts:
- `results/UNSW_NB15_baseline.txt`: Full metric and attack-category recall breakdown.
- `results/unsw_nb15_attack_recall.png`: Category-level detection recall bar chart.
- `results/unsw_nb15_roc_confusion.png`: Continuous score ROC curve and confusion matrix.

## Project structure

```text
SPECTRA-M4/
├── data/
│   ├── normal_telemetry.csv
│   ├── UNSW_NB15_training-set.csv
│   └── UNSW_NB15_testing-set.csv
├── results/
│   ├── isolation_forest.pkl
│   ├── risk_calibration.npz
│   ├── network_behavior.png
│   ├── UNSW_NB15_baseline.txt
│   ├── unsw_nb15_attack_recall.png
│   └── unsw_nb15_roc_confusion.png
├── src/
│   ├── paths.py
│   ├── generate_dataset.py
│   ├── train_model.py
│   ├── m4_interface.py
│   ├── risk_engine.py
│   ├── demo.py
│   ├── test_model.py
│   ├── evaluate_model.py
│   ├── evaluate_unsw_nb15.py
│   ├── anomaly_types_test.py
│   ├── visualize_results.py
│   └── visualize_unsw_nb15.py
└── README.md
```

## Limitations

The standalone M4 prototype still uses only four flow/telemetry features.
Cross-layer identity/session fusion and live M3 aggregation are not silently
claimed as implemented here. Those require additional integration work.
