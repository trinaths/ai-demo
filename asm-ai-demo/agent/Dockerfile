# Use a lightweight Python base image
FROM python:3.8-slim

# Set working directory
WORKDIR /app

# Install necessary dependencies
RUN pip install --no-cache-dir \
    flask \
    pandas \
    scikit-learn \
    joblib \
    numpy \
    kubernetes

# Copy the agent service application code to the container
COPY . /app/

# Expose the Flask app port
EXPOSE 8080

# Command to run the agent service
CMD ["python", "agent.py"]