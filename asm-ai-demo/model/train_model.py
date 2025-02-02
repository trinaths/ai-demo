import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import joblib
import os
import logging
import numpy as np

# Set up logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Paths
DATA_STORAGE_PATH = "/data/collected_traffic.csv"
MODEL_PATH = "/data/model.pkl"
ENCODERS_PATH = "/data/encoders.pkl"

# Ensure directory exists
os.makedirs("/data", exist_ok=True)

# Load dataset
logger.info("📥 Loading dataset for training...")
try:
    df = pd.read_csv(DATA_STORAGE_PATH, on_bad_lines="skip")

    # Validate required columns
    required_columns = [
        "response_code", "bytes_sent", "bytes_received", "request_rate", 
        "ip_reputation", "bot_signature", "violation", "prediction"
    ]
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise ValueError(f"❌ Missing columns in dataset: {', '.join(missing_columns)}")

except Exception as e:
    logger.error(f"❌ Error loading dataset: {e}")
    exit(1)

# Drop NaN values in required columns
df.dropna(subset=required_columns, inplace=True)

# **✅ Check if dataset is empty**
if df.empty:
    logger.error("❌ Dataset is empty after preprocessing. No training will be performed.")
    exit(1)

# Ensure 'prediction' column is binary
df["prediction"] = df["prediction"].astype(int)

# **✅ Ensure Balanced Dataset (Prevent Model Bias)**
malicious_df = df[df["prediction"] == 1]
normal_df = df[df["prediction"] == 0]

if malicious_df.empty or normal_df.empty:
    logger.error("❌ Dataset contains only one class (all malicious or all normal). Model training requires both classes.")
    exit(1)

# Balance dataset (equal malicious & normal samples)
min_size = min(len(malicious_df), len(normal_df))
malicious_df = malicious_df.sample(n=min_size, random_state=42)
normal_df = normal_df.sample(n=min_size, random_state=42)
df = pd.concat([malicious_df, normal_df]).sample(frac=1, random_state=42)  # Shuffle data

# Encode categorical variables
label_encoders = {}
for col in ["ip_reputation", "bot_signature", "violation"]:
    le = LabelEncoder()
    try:
        df[col] = le.fit_transform(df[col].astype(str))
        label_encoders[col] = le
    except Exception as e:
        logger.warning(f"⚠️ Error encoding column {col}: {e}")
        continue

# Define features and target
features = ["response_code", "bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation"]
target = "prediction"

# Prepare data
X = df[features]
y = df[target]

# **✅ Ensure dataset has samples before splitting**
if len(X) < 2:
    logger.error("❌ Insufficient data to split into training and testing sets.")
    exit(1)

# Split into training/testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
logger.info("🚀 Training model...")
model = RandomForestClassifier(n_estimators=150, random_state=42, class_weight="balanced")
model.fit(X_train, y_train)

# Evaluate model
y_pred = model.predict(X_test)
logger.info("📊 Model Evaluation Report:")
logger.info("\n" + classification_report(y_test, y_pred))

# Save model and encoders
try:
    joblib.dump(model, MODEL_PATH)
    joblib.dump(label_encoders, ENCODERS_PATH)
    logger.info("✅ Model trained and saved successfully!")
except Exception as e:
    logger.error(f"❌ Error saving model or encoders: {e}")
    exit(1)