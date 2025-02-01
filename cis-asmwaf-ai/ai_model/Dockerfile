# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Copy the trained model and scaler into the container
COPY ai_model.joblib /app/
COPY scaler.joblib /app/

# Install any needed dependencies specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 5000 for the Flask API
EXPOSE 5000

# Command to run the Flask app
CMD ["python", "app.py"]