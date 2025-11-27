# phishing_xgb_pipeline.py
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report

# -----------------------------
# 1. Load dataset
# -----------------------------
df = pd.read_csv("Training.csv")  # replace with your CSV path

# Encode target labels
y = df['status'].map({'legitimate': 0, 'phishing': 1})
X = df.drop(columns=['url', 'status'], errors='ignore')

# Separate numeric and categorical columns
numeric_cols = X.select_dtypes(include=np.number).columns.tolist()
categorical_cols = X.select_dtypes(include='object').columns.tolist()

print(f"Numeric cols: {len(numeric_cols)}, Categorical cols: {len(categorical_cols)}")

# -----------------------------
# 2. Train/test split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"Train/test sizes: {X_train.shape} {X_test.shape}")

# -----------------------------
# 3. Preprocessing pipeline
# -----------------------------
preprocessor = ColumnTransformer(
    transformers=[
        ("cat", OneHotEncoder(handle_unknown='ignore', sparse_output=True), categorical_cols),
        ("num", "passthrough", numeric_cols)
    ],
    sparse_threshold=1.0  # force sparse output for XGBoost
)

# -----------------------------
# 4. XGBoost classifier pipeline
# -----------------------------
pipeline = Pipeline([
    ("preprocessor", preprocessor),
    ("classifier", XGBClassifier(
        tree_method='hist',
        n_estimators=300,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        n_jobs=-1,
        eval_metric='logloss'
    ))
])

# -----------------------------
# 5. Train the pipeline
# -----------------------------
print("Training XGBoost pipeline...")
pipeline.fit(X_train, y_train)

# -----------------------------
# 6. Evaluate on test set
# -----------------------------
y_pred = pipeline.predict(X_test)
print("✅ Pipeline evaluation on test set")
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# -----------------------------
# 7. Save pipeline
# -----------------------------
joblib.dump(pipeline, "xgb_pipeline.pkl")
print("✅ Pipeline saved as xgb_pipeline.pkl")
