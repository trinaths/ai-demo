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
df = pd.read_csv(DATA_STORAGE_PATH, on_bad_lines='skip')

# **Ensure dataset is not empty**
if df.empty or "prediction" not in df.columns:
    logger.error("❌ Dataset is empty or missing the 'prediction' column. Exiting training.")
    exit(1)

# **Fix Class Imbalance**
normal_count = len(df[df["prediction"] == 0])
malicious_count = len(df[df["prediction"] == 1])

if normal_count == 0 or malicious_count == 0:
    logger.error(f"❌ Not enough data: {normal_count} normal vs {malicious_count} malicious.")
    exit(1)

logger.info(f"📊 Dataset contains {normal_count} normal vs {malicious_count} malicious samples.")

# **🧹 Handle missing values**
df.fillna({"violation": "None", "bot_signature": "Unknown", "ip_reputation": "Good"}, inplace=True)

# **🔹 Encode categorical variables**
label_encoders = {}
for col in ["ip_reputation", "bot_signature", "violation"]:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    label_encoders[col] = le

# **🛠 Feature selection**
features = [
    "response_code", "bytes_sent", "bytes_received", "request_rate",
    "ip_reputation", "bot_signature", "violation"
]

target = "prediction"

X = df[features]
y = df[target]

# **🧪 Split dataset into training & testing sets**
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# **🎯 Train model with optimized settings**
logger.info("🚀 Training optimized model...")
model = RandomForestClassifier(
    n_estimators=200,  
    max_depth=10,  # **Prevent overfitting**
    min_samples_split=8,  
    min_samples_leaf=4,  
    class_weight="balanced",  # **Compensates for class imbalance**
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