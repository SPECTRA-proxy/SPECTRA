# M4 Review Changes — 2026-10-08

## Implemented

1. Replaced sigmoid risk normalization with empirical percentile calibration against held-out normal traffic.
2. Added 80/20 normal train/calibration split.
3. Added calibrated policy thresholds: MFA at 0.97 and DROP at 0.995.
4. Added saved `results/risk_calibration.npz`.
5. Removed duplicated risk logic from `risk_engine.py`; it now uses `m4_interface.py`.
6. Changed inference to one `decision_function()` call and added latency reporting.
7. Made model/data/result paths independent of the current working directory.
8. Reworked synthetic evaluation to report FPR, ROC-AUC and latency and explicitly label it synthetic.
9. Added `evaluate_unsw_nb15.py` for real-dataset evaluation using the four-feature UNSW-NB15 mapping.
10. Updated README and demo output to explain the percentile interpretation.
11. Evaluated real UNSW-NB15 baseline (Precision 83.12%, Recall 17.78%, F1 29.29%, FPR 4.42%, ROC-AUC 0.7570, Median latency 5.720 ms, P95 latency 8.439 ms).
12. Added `results/UNSW_NB15_baseline.txt`, `src/visualize_unsw_nb15.py`, and real-dataset visual artifacts (`results/unsw_nb15_attack_recall.png`, `results/unsw_nb15_roc_confusion.png`).

## Not implemented yet

- M2 -> M4 HTTP integration. The current M2 repository still has a constant `0.12` risk stub.
- Live M3 window aggregation for request rate, connection count and inter-arrival time.
- Identity/location/device/time feature fusion.

## Demonstration values after recalibration

| Case | packet_size | request_rate | connection_count | inter_arrival_time | Risk | Decision |
|---|---:|---:|---:|---:|---:|---|
| Normal | 520 | 6 | 3 | 0.18 | 0.07 | ALLOW |
| Moderate | 523 | 8.4 | 4.8 | 0.143 | 0.98 | MFA / MONITOR |
| High | 9500 | 300 | 80 | 0.002 | 1.00 | DROP |

The previous 600 / 7 / 4 / 0.17 case now scores about 0.61 and is ALLOW, so it should not be used as the moderate-risk screenshot.
