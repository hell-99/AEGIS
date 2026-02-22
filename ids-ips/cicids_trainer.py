import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report
import joblib

MODEL_PATH   = "/home/twi/AEGIS/ids-ips/cicids_model.pkl"
SCALER_PATH  = "/home/twi/AEGIS/ids-ips/cicids_scaler.pkl"
ENCODER_PATH = "/home/twi/AEGIS/ids-ips/cicids_encoder.pkl"
DATA_PATH    = "/home/twi/AEGIS/ids-ips/cicids/cicids2017_cleaned.csv"

def load_and_clean():
    print("[CICIDS] Loading full dataset (2.5M rows)...")
    df = pd.read_csv(DATA_PATH, low_memory=False)
    print(f"[CICIDS] Loaded {len(df)} rows")

    # Show attack distribution
    print(f"\n[CICIDS] Attack distribution:")
    print(df['Attack Type'].value_counts())

    # Clean
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()

    # Balance dataset — sample equally from each class
    # This prevents model being biased toward Normal Traffic
    min_class = df['Attack Type'].value_counts().min()
    sample_size = min(min_class, 10000)  # max 10k per class
    print(f"\n[CICIDS] Balancing classes — {sample_size} samples per class")

    balanced = pd.concat([
        group.sample(min(len(group), sample_size), random_state=42)
        for _, group in df.groupby('Attack Type')
    ]).reset_index(drop=True)   

    print(f"[CICIDS] Balanced dataset: {len(balanced)} rows")
    print(balanced['Attack Type'].value_counts())

    X = balanced.drop(columns=['Attack Type'])
    y = balanced['Attack Type']
    X = X.select_dtypes(include=[np.number])

    return X, y

def train():
    X, y = load_and_clean()

    # Encode labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    print(f"\n[CICIDS] Classes: {list(le.classes_)}")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    # Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    # Train
    print(f"\n[CICIDS] Training Random Forest on {len(X_train)} balanced samples...")
    print("[CICIDS] Using all 5 CPU cores — estimated 3-5 minutes...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=25,
        n_jobs=-1,
        random_state=42,
        class_weight='balanced',
        verbose=1
    )
    model.fit(X_train_scaled, y_train)

    # Evaluate
    print("\n[CICIDS] Evaluating...")
    y_pred = model.predict(X_test_scaled)
    print("\n" + "="*60)
    print("CICIDS2017 FULL MODEL — 7 ATTACK TYPES")
    print("="*60)
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    # Feature importance
    importances = pd.Series(
        model.feature_importances_,
        index=X_train.columns
    ).sort_values(ascending=False)
    print("Top 10 Most Important Features:")
    print(importances.head(10))

    # Save everything
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(le, ENCODER_PATH)
    print(f"\n[CICIDS] Model saved!")
    print(f"[CICIDS] Classes: {list(le.classes_)}")
    print("[CICIDS] Training complete!")

if __name__ == "__main__":
    train()