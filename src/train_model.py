import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

from paths import CALIBRATION_PATH, MODEL_PATH, NORMAL_DATA_PATH, RESULTS_DIR

FEATURES = [
    "packet_size",
    "request_rate",
    "connection_count",
    "inter_arrival_time",
]

# Keep the split deterministic so calibration is reproducible.
RANDOM_STATE = 42
CALIBRATION_SIZE = 0.20

# Policy thresholds are based on the empirical percentile of held-out normal
# anomaly scores, not on an arbitrary sigmoid transformation.
MFA_RISK_THRESHOLD = 0.97
DROP_RISK_THRESHOLD = 0.995


def main():
    data = pd.read_csv(NORMAL_DATA_PATH)

    missing = [column for column in FEATURES if column not in data.columns]
    if missing:
        raise ValueError(f"Missing required features: {missing}")

    X = data[FEATURES].copy()

    # The model is trained only on normal traffic.
    X_train, X_calibration = train_test_split(
        X,
        test_size=CALIBRATION_SIZE,
        random_state=RANDOM_STATE,
        shuffle=True,
    )

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=RANDOM_STATE,
    )
    model.fit(X_train)

    # decision_function: larger = more normal.
    # Negating it makes larger values mean "more anomalous".
    calibration_anomaly_scores = -model.decision_function(X_calibration)
    calibration_anomaly_scores = np.sort(calibration_anomaly_scores.astype(float))

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    np.savez(
        CALIBRATION_PATH,
        anomaly_scores=calibration_anomaly_scores,
        mfa_threshold=MFA_RISK_THRESHOLD,
        drop_threshold=DROP_RISK_THRESHOLD,
    )

    print("========================================")
    print("       SPECTRA M4 MODEL TRAINING")
    print("========================================")
    print(f"Training samples   : {len(X_train)}")
    print(f"Calibration samples: {len(X_calibration)}")
    print(f"Features           : {len(FEATURES)}")
    print("Model              : Isolation Forest")
    print(f"MFA threshold      : risk >= {MFA_RISK_THRESHOLD:.3f}")
    print(f"DROP threshold     : risk >= {DROP_RISK_THRESHOLD:.3f}")
    print()
    print(f"Model saved        : {MODEL_PATH}")
    print(f"Calibration saved  : {CALIBRATION_PATH}")
    print("\nTraining and calibration completed successfully.")


if __name__ == "__main__":
    main()
