# Evaluation Report v2

Generated on: 2025-10-06T05:24:44.893019

## Key Metrics (on User-Level Holdout Set)

| Metric | Score |
|---|---|
| PR-AUC (Area Under PR Curve) | 0.9570 |
| ROC-AUC | 0.9952 |
| Best F1-Score | 0.9296 |
| Precision (at best F1) | 0.9775 |
| Recall (at best F1) | 0.8861 |
| Optimal Threshold | 0.3745 |

## Confusion Matrix (at Optimal Threshold)

```
[[36144    14]
 [   78   607]]
```

## Best Hyperparameters (from Optuna)

```json
{
  "n_estimators": 218,
  "max_depth": 5,
  "learning_rate": 0.022039761567996658
}
```
