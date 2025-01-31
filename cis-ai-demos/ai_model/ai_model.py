import pandas as pd
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import os

# Load Sample Data
df = pd.read_csv("raw_traffic_log.csv")

# Features & Labels
X = df[["request_rate", "bytes_transferred"]]
y = df["malicious"]

# Normalize Data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Build AI Model
model = tf.keras.Sequential([
    tf.keras.layers.Dense(16, activation='relu', input_shape=(X_train.shape[1],)),
    tf.keras.layers.Dense(8, activation='relu'),
    tf.keras.layers.Dense(1, activation='sigmoid')
])

# Compile & Train Model
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
model.fit(X_train, y_train, epochs=50, batch_size=4, verbose=1)

# Define Model Directory for TensorFlow Serving
MODEL_DIR = "models/anomaly_model/1"  # TensorFlow Serving requires versioning

# Ensure the model directory exists
os.makedirs(MODEL_DIR, exist_ok=True)

# Correct Way to Save Model for TensorFlow Serving
model.export(MODEL_DIR, overwrite=True)

print(f"Model Training Complete. Model saved at: {MODEL_DIR}")