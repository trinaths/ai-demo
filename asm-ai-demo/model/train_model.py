import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report
import joblib
import os
import logging
import numpy as np

# **🛠 Set up logging**
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# **📍 Paths**
DATA_STORAGE_PATH = "/data/collected_traffic.csv"
MODEL_PATH = "/data/model.pkl"
ENCODERS_PATH = "/data/encoders.pkl"
SCALER_PATH = "/data/scaler.pkl"

# **📂 Ensure directories exist**
os.makedirs("/data", exist_ok=True)

# **📥 Load dataset**
logger.info("📥 Loading dataset for training...")
try:
    df = pd.read_csv(DATA_STORAGE_PATH, on_bad_lines="skip")

    # **🚨 Validate required columns**
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

# **🚨 Handle missing values properly**
df.fillna({"violation": "None", "bot_signature": "Unknown", "ip_reputation": "Good"}, inplace=True)

# **🚀 Ensure 'prediction' column is binary**
df["prediction"] = df["prediction"].astype(int)

# **🔍 Check dataset size after filtering**
logger.info(f"📊 Dataset: {df.shape[0]} samples ({df['prediction'].value_counts().to_dict()})")

if df.shape[0] == 0:
    logger.error("❌ No data left after filtering. Exiting training.")
    exit(1)

# **📊 Balance dataset (Ensure equal normal & malicious samples)**
malicious_df = df[df["prediction"] == 1]
normal_df = df[df["prediction"] == 0]

if len(malicious_df) == 0 or len(normal_df) == 0:
    logger.error("❌ Imbalanced dataset: One class has zero samples.")
    exit(1)

min_size = min(len(malicious_df), len(normal_df))
malicious_df = malicious_df.sample(n=min_size, random_state=42)
normal_df = normal_df.sample(n=min_size, random_state=42)

df = pd.concat([malicious_df, normal_df]).sample(frac=1, random_state=42)  # **Shuffle dataset**

# **🔹 Encode categorical variables**
label_encoders = {}
for col in ["ip_reputation", "bot_signature", "violation"]:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    label_encoders[col] = le

# **📊 Feature & Target Selection**
features = ["bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation"]
target = "prediction"

X = df[features]
y = df[target]

# **🚨 Validate dataset before splitting**
if X.shape[0] == 0:
    logger.error("❌ No valid samples available for training. Exiting.")
    exit(1)

# **🚀 Apply StandardScaler**
scaler = StandardScaler()
X.loc[:, ["bytes_sent", "bytes_received", "request_rate"]] = scaler.fit_transform(X[["bytes_sent", "bytes_received", "request_rate"]])

# **🚀 Train/Test Split**
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

logger.info(f"📊 Training on {X_train.shape[0]} samples, Testing on {X_test.shape[0]} samples.")

# **🚀 Train Model**
logger.info("🚀 Training RandomForest model...")
model = RandomForestClassifier(n_estimators=150, random_state=42, class_weight="balanced")
model.fit(X_train, y_train)

# **📊 Evaluate Model**
y_pred = model.predict(X_test)
logger.info("📊 Model Evaluation Report:\n" + classification_report(y_test, y_pred))

# **💾 Save Model, Scaler & Encoders**
try:
    joblib.dump(model, MODEL_PATH)
    joblib.dump(label_encoders, ENCODERS_PATH)
    joblib.dump(scaler, SCALER_PATH)
    logger.info("✅ Model, Scaler, and Encoders saved successfully!")
except Exception as e:
    logger.error(f"❌ Error saving model: {e}")
    exit(1)