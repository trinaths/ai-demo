import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from imblearn.over_sampling import SMOTE
from sklearn.impute import SimpleImputer
from sklearn.utils import shuffle

# Load dataset (replace with the actual path to your CSV)
csv_filename = "improved_asm_training_data.csv"  # Update this path to your dataset
data = pd.read_csv(csv_filename)

# Data Preprocessing
# Drop non-numeric columns, and keep only necessary features
data = data.drop(columns=["timestamp", "src_ip", "request"])

# Convert categorical features to numeric (using label encoding)
data["violation"] = data["violation"].astype("category").cat.codes
data["bot_signature"] = data["bot_signature"].astype("category").cat.codes
data["severity"] = data["severity"].map({"Low": 0, "Medium": 1, "High": 2})
data["user_agent"] = data["user_agent"].astype("category").cat.codes
data["ip_reputation"] = data["ip_reputation"].map({"Good": 0, "Suspicious": 1, "Malicious": 2})

# Handle NaN values using SimpleImputer (fill missing data)
imputer = SimpleImputer(strategy="mean")
data.iloc[:, :-1] = imputer.fit_transform(data.iloc[:, :-1])

# Apply log transformation to handle skewed data
data["bytes_sent"] = np.log1p(data["bytes_sent"])
data["bytes_received"] = np.log1p(data["bytes_received"])
data["request_rate"] = np.log1p(data["request_rate"])

# Shuffle the dataset
data = shuffle(data, random_state=42)

# Separate features (X) and target (y)
X = data.drop(columns=["label"]).values  # Features (everything except 'label')
y = data["label"].values  # Target (the 'label' column)

# Normalize the features (standard scaling)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Apply SMOTE if label=1 is under 20% of dataset (to handle class imbalance)
malicious_ratio = np.sum(y) / len(y)
if malicious_ratio < 0.20:
    smote = SMOTE(sampling_strategy=0.2, random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X_scaled, y)
else:
    X_resampled, y_resampled = X_scaled, y

# Train-Test Split (70% training, 30% testing)
train_size = int(0.7 * len(X_resampled))
X_train, X_test = X_resampled[:train_size], X_resampled[train_size:]
y_train, y_test = y_resampled[:train_size], y_resampled[train_size:]

# Train the model (RandomForest as an example, but you can use MLP or other models)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate the model on the test set
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model accuracy: {accuracy:.4f}")

# Save the trained model and scaler as joblib files
joblib.dump(model, 'ai_model.joblib')
joblib.dump(scaler, 'scaler.joblib')

print("Model and scaler saved successfully.")