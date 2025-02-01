import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# Path to data storage
DATA_STORAGE_PATH = "/data/collected_traffic.csv"
MODEL_PATH = "/data/model.pkl"
ENCODERS_PATH = "/data/encoders.pkl"

# Ensure the directory exists
os.makedirs("/data", exist_ok=True)

# Load the initial dataset for training (must be uploaded before running this script)
print("Loading initial dataset for training...")

df = pd.read_csv(DATA_STORAGE_PATH)  # This must contain some initial traffic data

# Define features and target
features = ["response_code", "bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation"]
target = "label"  # The target label indicates malicious (1) or normal (0) traffic

# Encode categorical variables
label_encoders = {}
for col in ["ip_reputation", "bot_signature", "violation"]:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    label_encoders[col] = le

# Prepare data
X = df[features]
y = df[target]

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the model
print("Training initial model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save the trained model and encoders to the shared volume
joblib.dump(model, MODEL_PATH)
joblib.dump(label_encoders, ENCODERS_PATH)

print("Initial model trained and saved successfully!")