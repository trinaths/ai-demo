from flask import Flask, request, jsonify
import joblib
import numpy as np

# Load the trained model
model = joblib.load('ai_model.joblib')

# Initialize Flask app
app = Flask(__name__)

@app.route('/predict', methods=['POST'])
def predict():
    # Get the JSON request data
    data = request.get_json()

    # Extract the features from the request (expecting a list of feature values)
    features = np.array(data['features']).reshape(1, -1)

    # Normalize the features (same scaler used during training)
    scaler = joblib.load('scaler.joblib')  # Load the scaler (optional: save during training)
    features_scaled = scaler.transform(features)

    # Make prediction using the model
    prediction = model.predict(features_scaled)

    # Return the prediction as a JSON response
    return jsonify({'prediction': prediction[0]})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)