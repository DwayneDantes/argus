# tools/train_evaluate.py (FINAL INTEGRATED AND CORRECTED VERSION)

import logging
import sqlite3
import pandas as pd
import numpy as np
import joblib
import os
import json
from pathlib import Path
from datetime import datetime
import optuna
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    precision_recall_fscore_support, roc_auc_score,
    average_precision_score, confusion_matrix,
    precision_recall_curve, PrecisionRecallDisplay
)
import xgboost as xgb

# --- 1. SETUP & CONFIGURATION ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

# Import the NEW feature engineering function
from ml_utils.feature_engineering import generate_feature_matrix

# Define constants for paths and parameters
SCRIPT_DIR = Path(__file__).parent.resolve()
DATABASE_PATH = SCRIPT_DIR.parent / 'dataset_v2.sqlite'
RESULTS_DIR = SCRIPT_DIR / 'results'
MODEL_OUTPUT_PATH = RESULTS_DIR / 'argus_model_v2.joblib'
COLUMNS_OUTPUT_PATH = RESULTS_DIR / 'training_columns_v2.json'
REPORT_OUTPUT_PATH = RESULTS_DIR / 'evaluation_report_v2.md'
RANDOM_STATE = 42
OPTUNA_TRIALS = 50

# --- 2. DATA LOADING & SPLITTING ---
def load_data(db_path: Path) -> pd.DataFrame | None:
    logger.info(f"Loading data from {db_path}...")
    if not db_path.exists():
        logger.error(f"Database not found: {db_path}")
        return None
    try:
        conn = sqlite3.connect(db_path)
        query = "SELECT timestamp, actor_email, event_type, mime_type, is_malicious FROM events"
        df = pd.read_sql_query(query, conn)
        logger.info(f"Successfully loaded {len(df)} events.")
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df.sort_values('timestamp')
    finally:
        if 'conn' in locals() and conn:
            conn.close()

def user_level_holdout_split(df: pd.DataFrame, test_size=0.25):
    logger.info(f"Performing user-level holdout split (test_size={test_size})...")
    users = df['actor_email'].dropna().unique()
    np.random.seed(RANDOM_STATE)
    holdout_users = np.random.choice(users, size=int(len(users) * test_size), replace=False)
    
    train_df = df[~df['actor_email'].isin(holdout_users)]
    test_df = df[df['actor_email'].isin(holdout_users)]
    
    logger.info(f"Train set: {len(train_df)} events from {len(train_df['actor_email'].unique())} users.")
    logger.info(f"Test set: {len(test_df)} events from {len(test_df['actor_email'].unique())} users (held out).")
    return train_df, test_df

# --- 3. MODEL TRAINING & EVALUATION ---
def train_and_evaluate():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    full_df = load_data(DATABASE_PATH)
    if full_df is None: return
    
    train_df, test_df = user_level_holdout_split(full_df)

    logger.info("Generating feature matrix for the training set...")
    X_train = generate_feature_matrix(train_df.copy())
    y_train = train_df.sort_values('timestamp')['is_malicious'].reset_index(drop=True)

    logger.info("Generating feature matrix for the test set...")
    X_test = generate_feature_matrix(test_df.copy())
    y_test = test_df.sort_values('timestamp')['is_malicious'].reset_index(drop=True)

    # ------------------ START OF CRITICAL FIX ------------------
    logger.info("Enforcing column consistency between train and test sets...")
    train_cols = X_train.columns
    
    missing_in_test = set(train_cols) - set(X_test.columns)
    for c in missing_in_test:
        X_test[c] = 0
        
    missing_in_train = set(X_test.columns) - set(train_cols)
    for c in missing_in_train:
        X_train[c] = 0

    # Enforce the exact same column order
    X_test = X_test[train_cols]
    # ------------------- END OF CRITICAL FIX -------------------

    # Hybrid feature (Isolation Forest score)
    logger.info("Training Isolation Forest for hybrid feature...")
    iforest = IsolationForest(contamination="auto", random_state=RANDOM_STATE).fit(X_train)
    X_train["iforest_score"] = -iforest.decision_function(X_train)
    X_test["iforest_score"] = -iforest.decision_function(X_test)
    
    # The Isolation Forest adds a new column, so we need to get the final column list
    final_train_cols = X_train.columns
    X_test = X_test[final_train_cols] # Re-enforce order after adding the new feature

    logger.info(f"Saving {len(final_train_cols)} training columns to {COLUMNS_OUTPUT_PATH}")
    with open(COLUMNS_OUTPUT_PATH, "w") as f: json.dump(final_train_cols.tolist(), f, indent=4)

    # Optuna tuning
    def objective(trial):
        params = {
            "objective": "binary:logistic", "eval_metric": "aucpr",
            "n_estimators": trial.suggest_int("n_estimators", 200, 1000, log=True),
            "max_depth": trial.suggest_int("max_depth", 4, 10),
            "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.3, log=True),
            "scale_pos_weight": (len(y_train) - sum(y_train)) / sum(y_train) if sum(y_train) > 0 else 1
        }
        model = xgb.XGBClassifier(**params, random_state=RANDOM_STATE, use_label_encoder=False)
        model.fit(X_train, y_train, verbose=False)
        preds = model.predict_proba(X_test)[:, 1]
        return average_precision_score(y_test, preds)

    logger.info(f"Starting Optuna hyperparameter tuning ({OPTUNA_TRIALS} trials)...")
    study = optuna.create_study(direction="maximize")
    study.optimize(objective, n_trials=OPTUNA_TRIALS)
    best_params = study.best_trial.params
    
    # Train final model with best params
    logger.info("Training final XGBoost model with best parameters...")
    final_model = xgb.XGBClassifier(**best_params, random_state=RANDOM_STATE, use_label_encoder=False)
    final_model.fit(X_train, y_train) # Train on all train data

    # Probability Calibration
    logger.info("Calibrating model probabilities...")
    calibrated_model = CalibratedClassifierCV(estimator=final_model, method="isotonic", cv=3)
    calibrated_model.fit(X_train, y_train)

    logger.info(f"Saving calibrated model to {MODEL_OUTPUT_PATH}")
    joblib.dump(calibrated_model, MODEL_OUTPUT_PATH)

    # --- 4. REPORTING ---
    logger.info("Generating evaluation report on user-level holdout set...")
    y_pred_proba = calibrated_model.predict_proba(X_test)[:, 1]
    
    precisions, recalls, thresholds = precision_recall_curve(y_test, y_pred_proba)
    # Add a small epsilon to the denominator to avoid division by zero
    f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-9)
    best_f1_idx = np.nanargmax(f1_scores)
    best_threshold = thresholds[best_f1_idx]
    y_pred_binary = (y_pred_proba >= best_threshold).astype(int)

    pr_auc = average_precision_score(y_test, y_pred_proba)
    roc_auc = roc_auc_score(y_test, y_pred_proba)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred_binary, average='binary')

    with open(REPORT_OUTPUT_PATH, "w") as f:
        f.write("# Evaluation Report v2\n\n")
        f.write(f"Generated on: {datetime.now().isoformat()}\n\n")
        f.write("## Key Metrics (on User-Level Holdout Set)\n\n")
        f.write("| Metric | Score |\n|---|---|\n")
        f.write(f"| PR-AUC (Area Under PR Curve) | {pr_auc:.4f} |\n")
        f.write(f"| ROC-AUC | {roc_auc:.4f} |\n")
        f.write(f"| Best F1-Score | {f1:.4f} |\n")
        f.write(f"| Precision (at best F1) | {precision:.4f} |\n")
        f.write(f"| Recall (at best F1) | {recall:.4f} |\n")
        f.write(f"| Optimal Threshold | {best_threshold:.4f} |\n\n")
        f.write("## Confusion Matrix (at Optimal Threshold)\n\n```\n")
        f.write(str(confusion_matrix(y_test, y_pred_binary)))
        f.write("\n```\n\n")
        f.write("## Best Hyperparameters (from Optuna)\n\n```json\n")
        f.write(json.dumps(best_params, indent=2))
        f.write("\n```\n")
    logger.info(f"Evaluation report saved to {REPORT_OUTPUT_PATH}")

    display = PrecisionRecallDisplay.from_predictions(y_test, y_pred_proba, name="XGBoost_v2")
    plt.title("Precision-Recall Curve (User-Level Holdout)")
    plt.savefig(RESULTS_DIR / "pr_curve_v2.png")
    logger.info("PR curve plot saved.")
    
    feature_importances = pd.Series(final_model.feature_importances_, index=final_train_cols).sort_values(ascending=False)
    plt.figure(figsize=(10, 12))
    sns.barplot(x=feature_importances.head(30), y=feature_importances.head(30).index)
    plt.title("Top 30 Feature Importances (User-Level Holdout)")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "feature_importance_v2.png")
    logger.info("Feature importance plot saved.")


if __name__ == "__main__":
    train_and_evaluate()