from flask import Flask, jsonify, request
import time
import random

app = Flask(__name__)

@app.route('/inference', methods=['POST'])
def inference():
    # Simulate processing delay (50-200ms)
    time.sleep(random.uniform(0.05, 0.2))
    # Return a dummy prediction result
    return jsonify({"prediction": random.choice(["Accelerated", "AI", "app"])})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)