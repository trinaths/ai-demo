# Use Python 3.8 as the base image
FROM python:3.8

# Set the working directory
WORKDIR /app

# Copy AI Agent script
COPY ai_agent.py /app/

# Install dependencies
RUN pip install flask requests kubernetes

# Run AI Agent
CMD ["python3", "/app/ai_agent.py"]