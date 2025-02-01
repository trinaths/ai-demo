import joblib
import numpy as np
from flask import Flask, request, jsonify

# Initialize Flask app
app = Flask(__name__)

# Load the trained model and scaler
model = joblib.load('ai_model.joblib')
scaler = joblib.load('scaler.joblib')

# Function to preprocess incoming data (same as the one used during model training)
def preprocess_data(data):
    try:
        # Example feature extraction from incoming data
        ip_address = data.get("ip_address", "")
        http_method = data.get("http_method", "")
        uri = data.get("uri", "")
        status_code = data.get("status_code", 200)
        user_agent = data.get("user_agent", "")
        malicious = data.get("malicious", False)

        # Encode categorical features (e.g., http_method, user_agent, etc.)
        method_mapping = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3}
        method_encoded = method_mapping.get(http_method, -1)  # Default to -1 if method is unknown
        
        # Apply simple encoding for uri (length of the uri in characters)
        uri_encoded = len(uri)

        # Create feature vector for prediction
        feature_vector = np.array([[status_code, method_encoded, uri_encoded, malicious]])

        # Scale the features using the loaded scaler
        feature_vector_scaled = scaler.transform(feature_vector)

        return feature_vector_scaled

    except Exception as e:
        print(f"Error in preprocessing: {e}")
        return None

# Flask route to handle prediction requests
@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get the incoming JSON request
        request_data = request.get_json()

        if not request_data:
            return jsonify({"status": "error", "message": "No data provided"}), 400

        # Preprocess the data
        processed_data = preprocess_data(request_data)

        if processed_data is None:
            return jsonify({"status": "error", "message": "Error in preprocessing data"}), 500

        # Use the trained model to make a prediction
        prediction = model.predict(processed_data)

        # Convert prediction result to a dictionary response
        result = {
            "prediction": prediction.tolist()  # Ensure it's in list format for JSON serialization
        }

        return jsonify(result)

    except Exception as e:
        return jsonify({"status": "error", "message": f"Error occurred: {str(e)}"}), 500

# Main function to run the Flask app
if __name__ == '__main__':
    print("Starting AI Model API...")
    app.run(host='0.0.0.0', port=5000, debug=True)