# ML Model - XGBoost Risk Predictor

## Overview
Machine Learning model that predicts PR risk score (0-1) based on 12 engineered features.

## Structure
```
ml-model/
├── data/
│   ├── raw/                 # Raw PR data from GitHub
│   ├── processed/           # Cleaned & engineered features
│   └── .gitkeep
├── notebooks/
│   ├── data_collection.ipynb
│   ├── feature_engineering.ipynb
│   └── model_training.ipynb
├── models/
│   ├── xgboost_v1.pkl      # Trained model
│   └── .gitkeep
├── scripts/
│   ├── collect_data.py     # Scrape GitHub PRs
│   ├── train_model.py      # Training pipeline
│   └── evaluate.py         # Model evaluation
├── requirements.txt
└── README.md
```

## Features (12 Total)
- files_changed
- lines_added, lines_deleted
- commit_count
- author_reputation
- time_of_day, day_of_week
- has_test_changes
- num_issues, num_severity
- js/py_ratio
- historical_author_vulns_rate

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Collect training data
python scripts/collect_data.py

# Train model
python scripts/train_model.py

# Evaluate
python scripts/evaluate.py
```

## Target Metrics
- Accuracy: 75%+
- F1 Score: 0.80+
- ROC-AUC: 0.85+

## Owner
**Arjun** - Primary developer
