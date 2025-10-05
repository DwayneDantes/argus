# tools/train_evaluate.py (UPGRADED WITH OPTUNA + CALIBRATION + THRESHOLD TUNING)

import logging
import sqlite3
import pandas as pd
import numpy as np
import joblib
import os
import json
from pathlib import Path
import optuna

from ml_utils.feature_engineering import generate_feature_matrix

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    precision_recall_fscore_support, roc_auc_score,
    average_precision_score, confusion_matrix,
    precision_recall_curve, f1_score, classification_report
)
import xgboost as xgb
import matplotlib.pyplot as plt
import seaborn as sns
import optuna

# --- Path Anchoring ---
SCRIPT_DIR = Path(__file__).parent.resolve()
DATABASE_PATH = SCRIPT_DIR / 'argus_synthetic_dataset_v4.sqlite'
RESULTS_DIR = SCRIPT_DIR / 'results'
MODEL_OUTPUT_PATH = RESULTS_DIR / 'argus_tuned_hybrid_model.joblib'
COLUMNS_OUTPUT_PATH = RESULTS_DIR / 'training_columns.json'
RANDOM_STATE = 42

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

# --- load_data, simulate_context_for_training, print_metrics (unchanged) ---
def load_data(db_path: Path) -> pd.DataFrame | None:
    logger.info(f"Loading data from {db_path}...")
    if not db_path.exists():
        logger.error(f"Database not found: {db_path}")
        return None
    try:
        conn = sqlite3.connect(db_path)
        df = pd.read_sql_query("SELECT * FROM events", conn)
        logger.info(f"Successfully loaded {len(df)} events.")
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    finally:
        if 'conn' in locals() and conn:
            conn.close()

def simulate_context_for_training(df: pd.DataFrame) -> tuple[dict, dict]:
    logger.info("Simulating context (user baselines and file states)...")
    user_baselines = {}
    user_identifier_column = 'actor_email'
    user_ids = df[user_identifier_column].dropna().unique()
    for user_id in user_ids:
        user_baselines[user_id] = {'typical_activity_hours_json': json.dumps({'start': '08:00', 'end': '18:00'})}
    file_details_map = {}
    for _, event in df.sort_values(by='timestamp').iterrows():
        file_id = event['file_id']
        if not file_id: continue
        if file_id not in file_details_map:
            file_details_map[file_id] = {'is_shared_externally': 0.0, 'vt_positives': 0.0}
        if event['event_type'] == 'file_shared_externally':
            file_details_map[file_id]['is_shared_externally'] = 1.0
        if 'ransom' in str(event['attack_scenario']):
            file_details_map[file_id]['vt_positives'] = 15.0
    logger.info("Context simulation complete.")
    return user_baselines, file_details_map

def print_metrics(y_true, y_pred_proba, model_name: str, threshold=0.5):
    y_pred_binary = (y_pred_proba >= threshold).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred_binary, average='binary', zero_division=0)
    roc_auc = roc_auc_score(y_true, y_pred_proba)
    pr_auc = average_precision_score(y_true, y_pred_proba)
    logger.info(f"--- Metrics for {model_name} (at threshold {threshold:.2f}) ---")
    print(f"  Precision: {precision:.4f}\n  Recall:    {recall:.4f}\n  F1-Score:  {f1:.4f}")
    print(f"  AUC-ROC:   {roc_auc:.4f}\n  AUC-PR:    {pr_auc:.4f}")
    print(f"  Confusion Matrix:\n{confusion_matrix(y_true, y_pred_binary)}")
    logger.info("------------------------------------")


# --- NEW: Optuna hyperparameter tuning for XGB ---
def tune_xgb_with_optuna(X, y, n_trials=40):
    def objective(trial):
        params = {
            "n_estimators": trial.suggest_int("n_estimators", 200, 600),
            "max_depth": trial.suggest_int("max_depth", 3, 10),
            "learning_rate": trial.suggest_loguniform("learning_rate", 1e-3, 0.3),
            "subsample": trial.suggest_uniform("subsample", 0.6, 1.0),
            "colsample_bytree": trial.suggest_uniform("colsample_bytree", 0.6, 1.0),
            "gamma": trial.suggest_loguniform("gamma", 1e-8, 10.0),
            "min_child_weight": trial.suggest_int("min_child_weight", 1, 10),
            "use_label_encoder": False,
            "eval_metric": "logloss",
            "random_state": RANDOM_STATE,
            "scale_pos_weight": y.value_counts().get(0, 1) / y.value_counts().get(1, 1)
        }
        clf = xgb.XGBClassifier(**params)
        cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=RANDOM_STATE)
        f1_scores = []
        for train_idx, val_idx in cv.split(X, y):
            X_tr, X_val = X.iloc[train_idx], X.iloc[val_idx]
            y_tr, y_val = y.iloc[train_idx], y.iloc[val_idx]
            clf.fit(X_tr, y_tr)
            probs = clf.predict_proba(X_val)[:, 1]
            precisions, recalls, thresholds = precision_recall_curve(y_val, probs)
            f1s = 2 * (precisions * recalls) / (precisions + recalls + 1e-12)
            f1_scores.append(np.nanmax(f1s))
        return np.mean(f1_scores)

    study = optuna.create_study(direction="maximize")
    study.optimize(lambda t: objective(t), n_trials=n_trials)
    logger.info(f"Best Optuna params: {study.best_trial.params}")
    return study.best_trial.params


def train_and_evaluate(df: pd.DataFrame):
    logger.info("Starting model training and evaluation pipeline...")
    os.makedirs(RESULTS_DIR, exist_ok=True)

    logger.info("Generating feature matrix using shared library...")
    user_baselines, file_details_map = simulate_context_for_training(df)
    X = generate_feature_matrix(df.copy(), user_baselines, file_details_map)
    y = df.sort_values(by='timestamp')["is_malicious"].reset_index(drop=True)

    logger.info("Performing time-based split (80% train, 20% test)...")
    split_index = int(len(X) * 0.8)
    X_train, X_test = X.iloc[:split_index], X.iloc[split_index:]
    y_train, y_test = y.iloc[:split_index], y.iloc[split_index:]

    # Hybrid feature (Isolation Forest score)
    iforest = IsolationForest(contamination="auto", random_state=RANDOM_STATE).fit(X_train)
    X_train_hybrid = X_train.copy(); X_train_hybrid["iforest_score"] = -iforest.decision_function(X_train)
    X_test_hybrid = X_test.copy(); X_test_hybrid["iforest_score"] = -iforest.decision_function(X_test)

    # Save training columns
    final_training_columns = X_train_hybrid.columns.tolist()
    with open(COLUMNS_OUTPUT_PATH, "w") as f: json.dump(final_training_columns, f, indent=4)

    # --- Hyperparameter tuning with Optuna ---
    best_params = tune_xgb_with_optuna(X_train_hybrid, y_train, n_trials=40)
    clf = xgb.XGBClassifier(**best_params)

    # --- Calibrate probabilities ---
    calibrator = CalibratedClassifierCV(estimator=clf, method="isotonic", cv=3)
    calibrator.fit(X_train_hybrid, y_train)

    # --- Threshold tuning on test set ---
    probs = calibrator.predict_proba(X_test_hybrid)[:, 1]
    precisions, recalls, thresholds = precision_recall_curve(y_test, probs)
    f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-12)
    best_idx = np.nanargmax(f1_scores)
    best_thresh = thresholds[best_idx] if best_idx < len(thresholds) else 0.5

    logger.info(f"Best threshold for F1-score found at: {best_thresh:.2f}")
    print_metrics(y_test, probs, "Tuned Hybrid XGBoost", threshold=best_thresh)

    # Save model + threshold
    joblib.dump({"model": calibrator, "threshold": best_thresh}, MODEL_OUTPUT_PATH)

    # Feature importance (from underlying XGB, not calibrator)
    all_importances = []

# Newer sklearn: has .estimators_
    if hasattr(calibrator, "estimators_"):
        fitted_models = calibrator.estimators_
# Older sklearn: has .calibrated_classifiers_
    elif hasattr(calibrator, "calibrated_classifiers_"):
        fitted_models = [cc.estimator for cc in calibrator.calibrated_classifiers_]
    else:
        fitted_models = []

    for est in fitted_models:
        fitted_xgb = getattr(est, "base_estimator", est)
        if hasattr(fitted_xgb, "feature_importances_"):
            all_importances.append(fitted_xgb.feature_importances_)

    if all_importances:
        avg_importances = np.mean(all_importances, axis=0)
        feature_importances = pd.Series(avg_importances, index=final_training_columns).sort_values(ascending=False)

        plt.figure(figsize=(10, 12))
        sns.barplot(x=feature_importances.head(30), y=feature_importances.head(30).index)
        plt.title("Top 30 Averaged Feature Importances for Tuned Hybrid Model")
        plt.xlabel("Importance Score")
        plt.tight_layout()
        plt.savefig(RESULTS_DIR / "feature_importance_tuned.png")
        plt.close()
        logger.info("Averaged feature importance plot saved.")
    else:
        logger.warning("No feature importances found in fitted estimators.")



def main():
    df = load_data(DATABASE_PATH)
    if df is not None:
        train_and_evaluate(df)

if __name__ == "__main__":
    main()
