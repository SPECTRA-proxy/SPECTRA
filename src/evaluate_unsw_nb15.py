"""Evaluate M4 on UNSW-NB15 CSV files.

Expected files:
  data/UNSW_NB15_training-set.csv
  data/UNSW_NB15_testing-set.csv

The mapping intentionally stays limited to the four M4 features:
  smean       -> packet_size
  rate        -> request_rate
  ct_srv_src  -> connection_count
  sinpkt(ms)  -> inter_arrival_time(seconds)

M4 remains unsupervised: training uses only label == 0 rows from the training
file. Threshold calibration uses a held-out normal split from those rows.
"""

from pathlib import Path
import argparse
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

FEATURES = [
    "packet_size",
    "request_rate",
    "connection_count",
    "inter_arrival_time",
]

MFA_THRESHOLD = 0.97
DROP_THRESHOLD = 0.995
RANDOM_STATE = 42

UNSW_COLUMNS = {
    "smean": "packet_size",
    "rate": "request_rate",
    "ct_srv_src": "connection_count",
    "sinpkt": "inter_arrival_time",
}


def load_and_map(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    missing = [c for c in [*UNSW_COLUMNS, "label"] if c not in df.columns]
    if missing:
        raise ValueError(f"{path} is missing columns: {missing}")

    mapped = df.rename(columns=UNSW_COLUMNS).copy()
    mapped["inter_arrival_time"] = mapped["inter_arrival_time"] / 1000.0

    mapped = mapped[FEATURES + ["label"]].replace([np.inf, -np.inf], np.nan).dropna()
    return mapped


def calibrate(model, normal_calibration: pd.DataFrame):
    ref = np.sort(-model.decision_function(normal_calibration[FEATURES]))
    return ref


def percentile_risk(model, ref, data):
    scores = -model.decision_function(data[FEATURES])
    positions = np.searchsorted(ref, scores, side="right")
    return np.clip(positions / len(ref), 0.0, 1.0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", default="data/UNSW_NB15_training-set.csv")
    parser.add_argument("--test", default="data/UNSW_NB15_testing-set.csv")
    args = parser.parse_args()

    train = load_and_map(Path(args.train))
    test = load_and_map(Path(args.test))

    normal_train = train[train["label"] == 0].copy()
    if normal_train.empty:
        raise ValueError("No label==0 normal rows found in training data.")

    normal_fit, normal_calibration = train_test_split(
        normal_train,
        test_size=0.20,
        random_state=RANDOM_STATE,
    )

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=RANDOM_STATE,
    )
    model.fit(normal_fit[FEATURES])
    ref = calibrate(model, normal_calibration)

    risk = percentile_risk(model, ref, test)
    y_true = test["label"].astype(int).to_numpy()
    y_pred = (risk >= MFA_THRESHOLD).astype(int)

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    auc = roc_auc_score(y_true, risk)
    cm = confusion_matrix(y_true, y_pred)
    fpr = cm[0, 1] / cm[0].sum() if cm[0].sum() else 0.0

    # Single-sample latency measurement.
    sample = test[FEATURES].iloc[[0]]
    for _ in range(20):
        model.decision_function(sample)
    timings = []
    for _ in range(100):
        start = time.perf_counter()
        model.decision_function(sample)
        timings.append((time.perf_counter() - start) * 1000)

    print("========================================")
    print("       SPECTRA M4 UNSW-NB15 EVALUATION")
    print("========================================")
    print(f"Training rows (normal only): {len(normal_fit)}")
    print(f"Calibration rows (normal)  : {len(normal_calibration)}")
    print(f"Testing rows               : {len(test)}")
    print("\nFeature mapping:")
    for source, target in UNSW_COLUMNS.items():
        if source != "sinpkt":
            print(f"  {source:14} -> {target}")
        else:
            print(f"  {source:14} -> {target} (ms / 1000)")

    print("\n----------------------------------------")
    print("Overall test metrics")
    print("----------------------------------------")
    print(f"Precision          : {precision:.4f}")
    print(f"Recall             : {recall:.4f}")
    print(f"F1-score           : {f1:.4f}")
    print(f"ROC-AUC            : {auc:.4f}")
    print(f"False-positive rate : {fpr:.4f}")
    print(f"Median latency     : {np.median(timings):.3f} ms")
    print(f"P95 latency        : {np.percentile(timings, 95):.3f} ms")

    if "attack_cat" in pd.read_csv(args.test, nrows=1).columns:
        raw_test = pd.read_csv(args.test)
        attack_cat = raw_test.loc[test.index, "attack_cat"] if len(raw_test) == len(test) else None
        # Index alignment can be affected by dropna. Re-read and map with an
        # explicit row id if per-category reporting is needed.
        if attack_cat is not None:
            print("\nPer attack category recall:")
            for category in sorted(attack_cat.dropna().unique()):
                mask = (attack_cat == category).to_numpy()
                if mask.sum():
                    print(f"  {str(category):20} {recall_score(y_true[mask], y_pred[mask], zero_division=0):.4f}")

    print("\nConfusion matrix:")
    print(cm)
    print("\nUse these results as the real-dataset evaluation in the review.")


if __name__ == "__main__":
    main()
