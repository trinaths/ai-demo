# Use TensorFlow Serving as the base image
FROM tensorflow/serving:latest

# Copy the trained AI model into the container
COPY models/anomaly_model_tf /models/anomaly_model_tf

# Set environment variables for TensorFlow Serving
ENV MODEL_NAME=anomaly_model
ENV MODEL_BASE_PATH=/models/anomaly_model_tf

# ✅ Correct ENTRYPOINT Syntax for TensorFlow Serving
ENTRYPOINT ["/usr/bin/tensorflow_model_server", \
            "--port=8500", \
            "--rest_api_port=8501", \
            "--model_name=anomaly_model_tf", \
            "--model_base_path=/models/anomaly_model_tf"]