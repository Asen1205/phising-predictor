import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier

# -----------------------------

# 1. Initialize models

# -----------------------------

model_content = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1,
    warm_start=True  # allows incremental training
)

model_struct = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1,
    warm_start=True
)

content_cols = []  # will be determined from first chunk
struct_cols = []

# -----------------------------

# 2. Load dataset in chunks

# -----------------------------

chunksize = 10000  # adjust depending on memory
for chunk in pd.read_csv("Training.csv", chunksize=chunksize):
    y = chunk['status']  # target column
    X = chunk.drop(columns=['url', 'status'])

    # Convert to numeric
    X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

    # Determine content & structural columns from first chunk
    if not content_cols:
        content_cols = [c for c in X.columns if 'url_has' in c or 'url_len' in c or 'path' in c]
        struct_cols = [c for c in X.columns if c not in content_cols]

    X_content = X[content_cols]
    X_struct = X[struct_cols]

    # Incremental fit
    # When warm_start=True, increasing n_estimators and calling fit will add trees
    model_content.n_estimators += 10  # increase trees slightly per batch
    model_struct.n_estimators += 10

    model_content.fit(X_content, y)
    model_struct.fit(X_struct, y)

# -----------------------------

# 3. Save models and column info

# -----------------------------

joblib.dump(model_content, "model_content.pkl")
joblib.dump(model_struct, "model_structural.pkl")
joblib.dump(content_cols, "X_content_cols.pkl")
joblib.dump(struct_cols, "X_struct_cols.pkl")

print("✅ Batch training completed and models saved!")
