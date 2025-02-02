import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, precision_score, recall_score, f1_score
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

# **🔹 Encode categorical variables**
label_encoders = {}
for col in ["ip_reputation", "bot_signature", "violation"]:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    label_encoders[col] = le

# **🛠 Feature selection using feature importance**
features = ["response_code", "bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation"]
target = "prediction"

X = df[features]
y = df[target]

# **🧪 Split dataset into training & testing sets**
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# **🎯 Train model with optimized hyperparameters**
logger.info("🚀 Training optimized model...")
model = RandomForestClassifier(
    n_estimators=200,  # Increased trees for better performance
    max_depth=10,  # Prevents overfitting
    min_samples_split=5,  # Ensures better decision making
    min_samples_leaf=3,  # Reduces variance
    random_state=42
)
model.fit(X_train, y_train)

# **📊 Evaluate model**
y_pred = model.predict(X_test)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

logger.info("📊 Model Evaluation Metrics:")
logger.info(f"   🎯 Precision: {precision:.4f}")
logger.info(f"   🎯 Recall: {recall:.4f}")
logger.info(f"   🎯 F1 Score: {f1:.4f}")

# **📉 Feature importance analysis**
feature_importance = pd.DataFrame({"Feature": features, "Importance": model.feature_importances_})
feature_importance = feature_importance.sort_values(by="Importance", ascending=False)

logger.info("📊 Feature Importance Ranking:")
logger.info("\n" + feature_importance.to_string(index=False))

# **💾 Save trained model & encoders**
try:
    joblib.dump(model, MODEL_PATH)
    joblib.dump(label_encoders, ENCODERS_PATH)
    logger.info("✅ Model and encoders saved successfully!")
except Exception as e:
    logger.error(f"❌ Error saving model: {e}")
    exit(1)