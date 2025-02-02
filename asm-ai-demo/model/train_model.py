import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
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

try:
    df = pd.read_csv(DATA_STORAGE_PATH, on_bad_lines='skip')  # Skip malformed lines

    # Validate required columns exist
    required_columns = ["response_code", "bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation", "label"]
    missing_columns = [col for col in required_columns if col not in df.columns]

    if missing_columns:
        raise ValueError(f"Missing columns in the dataset: {', '.join(missing_columns)}")

except Exception as e:
    print(f"Error loading dataset: {e}")
    exit(1)

# Handle missing values
df = df.dropna(subset=["response_code", "bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation", "label"])

# Encode categorical variables
label_encoders = {}
for col in ["ip_reputation", "bot_signature", "violation"]:
    le = LabelEncoder()
    try:
        df[col] = le.fit_transform(df[col].astype(str))
        label_encoders[col] = le
    except Exception as e:
        print(f"Error encoding column {col}: {e}")
        continue

# Define features and target
features = ["response_code", "bytes_sent", "bytes_received", "request_rate", "ip_reputation", "bot_signature", "violation"]
target = "label"  # The target label indicates malicious (1) or normal (0) traffic

# Prepare data
X = df[features]
y = df[target]

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the model
print("Training initial model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
print("Model Evaluation Report:")
print(classification_report(y_test, y_pred))

# Save the trained model and encoders to the shared volume
try:
    joblib.dump(model, MODEL_PATH)
    joblib.dump(label_encoders, ENCODERS_PATH)
    print("Initial model trained and saved successfully!")
except Exception as e:
    print(f"Error saving model or encoders: {e}")
    exit(1)