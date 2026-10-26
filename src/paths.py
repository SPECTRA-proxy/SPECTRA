from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
RESULTS_DIR = ROOT / "results"
MODEL_PATH = RESULTS_DIR / "isolation_forest.pkl"
CALIBRATION_PATH = RESULTS_DIR / "risk_calibration.npz"
NORMAL_DATA_PATH = DATA_DIR / "normal_telemetry.csv"
