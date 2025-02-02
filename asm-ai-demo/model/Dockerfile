# Use a lightweight Python base image
FROM python:3.8-slim

# Set working directory
WORKDIR /app

# Install necessary dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the model retraining application code to the container
COPY . /app/

# Expose the Flask app port (if needed for testing)
EXPOSE 5000

# Command to run the model retraining script
CMD ["python", "train_model.py"]