import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import joblib
import os
import logging

# **🛠 Set up Logging**
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# **📍 Paths**
DATA_STORAGE_PATH = "/data/collected_traffic.csv"
MODEL_PATH = "/data/model.pkl"
ENCODERS_PATH = "/data/encoders.pkl"

# **📂 Ensure directories exist**
os.makedirs("/data", exist_ok=True)

# **📥 Load dataset**
logger.info("📥 Loading dataset for training...")
try:
    df = pd.read_csv(DATA_STORAGE_PATH, on_bad_lines='skip')

    # **Validate required columns**
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

# **🧹 Handle missing values**
df = df.dropna(subset=required_columns)

# **📉 Fix Class Imbalance**
normal_count = len(df[df["prediction"] == 0])
malicious_count = len(df[df["prediction"] == 1])

if normal_count < malicious_count:
    df_malicious = df[df["prediction"] == 1].sample(normal_count, random_state=42)
    df_normal = df[df["prediction"] == 0]
    df = pd.concat([df_malicious, df_normal])
    logger.info(f"📊 Balanced dataset: {len(df[df['prediction']==0])} normal vs {len(df[df['prediction']==1])} malicious.")

# **🔹 Encode categorical variables**
label_encoders = {}
for col in ["ip_reputation", "bot_signature", "violation"]:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    label_encoders[col] = le

# **🛠 Feature selection**
features = ["response_code", "bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation"]
target = "prediction"

X = df[features]
y = df[target]

# **🧪 Split dataset into training & testing sets**
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# **🎯 Train model with regularization**
logger.info("🚀 Training optimized model...")
model = RandomForestClassifier(
    n_estimators=100,  
    max_depth=8,  # **Reduce depth to prevent overfitting**
    min_samples_split=10,  # **Higher value ensures generalization**
    min_samples_leaf=5,  # **Avoids learning noise**
    class_weight="balanced",  # **Compensates for any remaining class imbalance**
    random_state=42
)
model.fit(X_train, y_train)

# **📊 Evaluate model**
y_pred = model.predict(X_test)
logger.info("📊 Model Evaluation Metrics:")
logger.info(classification_report(y_test, y_pred))

# **💾 Save trained model & encoders**
try:
    joblib.dump(model, MODEL_PATH)
    joblib.dump(label_encoders, ENCODERS_PATH)
    logger.info("✅ Model and encoders saved successfully!")
except Exception as e:
    logger.error(f"❌ Error saving model: {e}")
    exit(1)