import pandas as pd
import joblib
import os
import logging
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.utils import shuffle
from sklearn.metrics import classification_report
import numpy as np

# **🛠 Set up logging**
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# **📂 Paths**
DATA_STORAGE_PATH = "/data/collected_traffic.csv"
MODEL_PATH = "/data/model.pkl"
ENCODERS_PATH = "/data/encoders.pkl"

# **📂 Ensure directories exist**
os.makedirs("/data", exist_ok=True)

# **📥 Load dataset**
logger.info("📥 Loading dataset for training...")
df = pd.read_csv(DATA_STORAGE_PATH, on_bad_lines='skip')

# **🚨 Ensure dataset is valid**
if df.empty or "prediction" not in df.columns:
    logger.error("❌ Dataset is empty or missing 'prediction' column. Exiting training.")
    exit(1)

# **🔍 Check dataset balance**
normal_count = df[df["prediction"] == 0].shape[0]
malicious_count = df[df["prediction"] == 1].shape[0]

logger.info(f"📊 Dataset: {normal_count} normal vs {malicious_count} malicious.")

if normal_count == 0 or malicious_count == 0:
    logger.error("❌ Not enough data in either class. Exiting.")
    exit(1)

# **🧹 Handle missing values**
df.fillna({"violation": "None", "bot_signature": "Unknown", "ip_reputation": "Good"}, inplace=True)

# **🚨 Feature Engineering**
# Remove `response_code` (leakage) and create new features
df["request_size_ratio"] = df["bytes_sent"] / (df["bytes_received"] + 1)  # Avoid division by zero
df["request_rate_norm"] = np.log(df["request_rate"] + 1)  # Normalize request rate

# **📊 Check for Feature Correlation**
correlation = df.corr(numeric_only=True)["prediction"].abs().sort_values(ascending=False)
logger.info("📊 Feature Correlation with 'prediction':\n%s", correlation)

# **❌ Remove Leaky Features (`response_code`)**
features = [
    "bytes_sent", "bytes_received", "request_rate_norm",
    "request_size_ratio", "ip_reputation", "bot_signature"
]
target = "prediction"

# **🔹 Encode categorical variables**
label_encoders = {}
for col in ["ip_reputation", "bot_signature"]:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    label_encoders[col] = le

# **🚀 Shuffle dataset to prevent order bias**
df = shuffle(df, random_state=42)

# **🔄 Balance dataset dynamically if imbalance exists**
min_samples = min(normal_count, malicious_count)
df_normal_balanced = df[df["prediction"] == 0].sample(min_samples, random_state=42)
df_malicious_balanced = df[df["prediction"] == 1].sample(min_samples, random_state=42)

# **Merge balanced dataset**
df_balanced = pd.concat([df_normal_balanced, df_malicious_balanced])

# **🎯 Train-test split**
X_train, X_test, y_train, y_test = train_test_split(
    df_balanced[features], df_balanced["prediction"], test_size=0.2, stratify=df_balanced["prediction"], random_state=42
)

# **🎛 Grid Search for Best Hyperparameters**
param_grid = {
    "n_estimators": [100, 150, 200],
    "max_depth": [5, 7, 10],
    "min_samples_split": [5, 10],
    "min_samples_leaf": [2, 5, 10],
    "class_weight": ["balanced"]
}

rf_model = RandomForestClassifier(random_state=42)

grid_search = GridSearchCV(rf_model, param_grid, cv=3, scoring="accuracy", n_jobs=-1)
grid_search.fit(X_train, y_train)

best_params = grid_search.best_params_
logger.info(f"✅ Best Model Parameters: {best_params}")

# **🚀 Train Optimized Model**
logger.info("🚀 Training optimized model with best parameters...")
model = RandomForestClassifier(**best_params, random_state=42)
model.fit(X_train, y_train)

# **📊 Cross-Validation**
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cross_val_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="accuracy")

logger.info(f"📊 Cross-Validation Accuracy Scores: {cross_val_scores}")
logger.info(f"📈 Average CV Accuracy: {cross_val_scores.mean():.4f}")

# **📊 Evaluate model**
y_pred = model.predict(X_test)
logger.info("📊 Model Evaluation Metrics:")
logger.info("\n%s", classification_report(y_test, y_pred))

# **💾 Save trained model & encoders**
try:
    joblib.dump(model, MODEL_PATH)
    joblib.dump(label_encoders, ENCODERS_PATH)
    logger.info("✅ Model and encoders saved successfully!")
except Exception as e:
    logger.error(f"❌ Error saving model: {e}")
    exit(1)