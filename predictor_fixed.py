import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier

model_content = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1,
    warm_start=True  
)

model_struct = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1,
    warm_start=True
)

content_cols = [] 
struct_cols = []

chunksize = 10000
for chunk in pd.read_csv("Training.csv", chunksize=chunksize):
    y = chunk['status']
    X = chunk.drop(columns=['url', 'status'])

    X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

    if not content_cols:
        content_cols = [c for c in X.columns if 'url_has' in c or 'url_len' in c or 'path' in c]
        struct_cols = [c for c in X.columns if c not in content_cols]

    X_content = X[content_cols]
    X_struct = X[struct_cols]

    model_content.n_estimators += 10
    model_struct.n_estimators += 10

    model_content.fit(X_content, y)
    model_struct.fit(X_struct, y)

joblib.dump(model_content, "model_content.pkl")
joblib.dump(model_struct, "model_structural.pkl")
joblib.dump(content_cols, "X_content_cols.pkl")
joblib.dump(struct_cols, "X_struct_cols.pkl")

print("✅ Batch training completed and models saved!")

