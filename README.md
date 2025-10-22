# AWS IAM Threat Detection System using LSTM Model

A production-ready AI-powered threat detection system that monitors AWS CloudTrail events in real-time to detect malicious IAM activities using deep learning and context-aware analysis.

## 🎯 Project Overview

This system provides **real-time threat detection** for AWS environments by:
- **Direct CloudTrail API integration** for live event monitoring
- **LSTM neural network** analysis for pattern recognition
- **Context-aware intelligence** to recognize false positives
- **Dockerized TensorFlow model** deployment to AWS Lambda via ECR
- **Automated S3 storage** for audit trails and compliance

## 🏗️ Project System Architecture

```
AWS CloudTrail → EventBridge → Lambda (from ECR) → DynamoDB → CloudWatch
```

The **TensorFlow LSTM model** is packaged in a **Docker container** and pushed to **Amazon ECR**, allowing Lambda to perform real-time inference when triggered by IAM events from CloudTrail.

## 🚀 Quick Start Guide

### 1. Prerequisites (IMPORTANT!!!)
```bash
# Required software
Python 3.8+
AWS CLI configured with appropriate permissions
TensorFlow 2.x
Docker Desktop or CLI
boto3

# Install dependencies
pip install tensorflow boto3 scikit-learn pandas numpy

# Dataset
Make sure you have the `flaws_cloudtrail_logs` folder in the root directory because this is the main dataset which is too big to be upload to Github. It should contain the following extracted files:
- flaws_cloudtrail01.json
- flaws_cloudtrail05.json
- flaws_cloudtrail10.json
- flaws_cloudtrail14.json
- flaws_cloudtrail19.json

There is also a missing file `lstm_sequences.npy` which should also be in the root directory but is also too big to be upload to Github.
```

### 2. Training the Model (OPTIONAL)
Training the model is optional since the final product of the model (**iam_threat_production_model.h5**) has already been uploaded to Github
```bash
python train_production_model.py
```

### 3. Docker Setup and Deployment

#### 3.1 Build and Test Docker Image Locally
```bash
docker build -t tf-infer-image .
```

#### 3.2 Authenticate Docker to Amazon ECR
```bash
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com
```

#### 3.3 Tag and Push Image to ECR
```bash
docker tag tf-infer-image:latest <account-id>.dkr.ecr.us-east-1.amazonaws.com/tf-infer-image:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/tf-infer-image:latest
```

#### 3.4 Create or Update Lambda Function from ECR Image
```bash
aws lambda create-function   --function-name tf-infer-lambda   --package-type Image   --code ImageUri=<account-id>.dkr.ecr.us-east-1.amazonaws.com/tf-infer-image:latest   --role arn:aws:iam::<account-id>:role/LambdaExecutionRole
```
> **Note:** You can update later using:
```bash
aws lambda update-function-code   --function-name tf-infer-lambda   --image-uri <account-id>.dkr.ecr.us-east-1.amazonaws.com/tf-infer-image:latest
```

### 4. AWS Setup
```bash
# Ensure AWS credentials are configured
aws configure

# Verify CloudTrail access
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity --max-items 1

# Create S3 bucket for results (optional)
aws s3 mb s3://your-threat-detection-bucket
```

### 5. Running Threat Detection
```bash
# Run real-time threat analysis (default: 7 days)
python threat_detector.py

# Analyze specific time range
python threat_detector.py --days 1
OR
python threat_detector.py --hours 12

# Use custom configuration
python threat_detector.py --config custom_config.json
```

## 📊 Attack Test Cases

### **Privilege Escalation Detection**
```bash
aws iam create-user --user-name malicious-user
aws iam create-access-key --user-name malicious-user
aws iam attach-user-policy --user-name malicious-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### **Lateral Movement Detection**
```bash
aws iam create-role --role-name lateral-role-1 --assume-role-policy-document file://trust-policy.json
aws iam attach-role-policy --role-name lateral-role-1 --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess
```

### **Data Exfiltration**
```bash
aws iam create-user --user-name data-exfil-user
aws iam create-access-key --user-name data-exfil-user
aws iam attach-user-policy --user-name data-exfil-user --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

### **Reconnaissance Testing**
```bash
aws iam list-users --max-items 1000
aws iam list-roles --max-items 1000
aws iam list-policies --scope Local --max-items 1000
```

## 🧠 Context-Aware Intelligence

### **Trust Signals (Reduce False Positives):**
- ✅ MFA authenticated sessions
- ✅ CloudShell/Console source
- ✅ Business hours activity
- ✅ Known IP addresses

### **Risk Signals (Increase Threat Score):**
- ⚠️ Very off-hours activity (2 AM - 6 AM)
- ⚠️ External IP sources
- ⚠️ No MFA authentication
- ⚠️ Rapid API call sequences

## 📁 Core Files

### **Production System:**
- **`threat_detector.py`** - Main real-time threat detection system
- **`threat_detector_config.json`** - Configuration file
- **`trust-policy.json`** - IAM policy for testing

### **Training Pipeline (Historical):**
- **`train_production_model.py`** - LSTM model training
- **`cloudtrail_processor.py`** - Feature engineering
- **`lstm_model.py`** - Neural network architecture
- **`run_pipeline.py`** - End-to-end training workflow

### **Trained Model Files:**
- **`iam_threat_production_model.h5`** - Trained LSTM model (523KB)
- **`production_label_encoder.pkl`** - Event type encoder
- **`production_threshold.pkl`** - Optimized threshold (0.88)
- **`production_metadata.pkl`** - Training metadata

## 📊 Output & Results

### **Local Output Files:**
```
threat_analysis_output/
├── threat_analysis_report_20251019_160230.json    # Detailed threat analysis
└── all_events_20251019_160230.json                # Complete event logs
```

### **S3 Automated Upload:**
```
s3://lstm-model-output/
├── analysis-reports/
│   └── threat_analysis_report_20251019_160230.json
└── all-events/
    └── all_events_20251019_160230.json
```

### **Sample Analysis Report:**
```json
{
  "threat_analysis": {
    "threat_type": "Privilege_Escalation",
    "confidence": 0.895,
    "is_threat": true,
    "risk_level": "HIGH",
    "malicious_events_breakdown": {
      "privilege_escalation": [
        {
          "EventName": "CreateUser",
          "EventTime": "2025-10-19T14:45:48+08:00",
          "EventId": "176e1ecc-0c6c-41e7-94bb-70a9d49f3dce",
          "Username": "ProjectAdmin"
        }
      ]
    }
  }
}
```

# Anomaly Guard Dashboard

The **Anomaly Guard Dashboard** is a Streamlit-based web application that visualizes AWS anomaly detection results in real time.
It automatically retrieves and displays the latest JSON files stored in your AWS S3 bucket, allowing you to monitor anomaly trends, event counts, and timelines.

## 1. Installation
```bash
git clone https://github.com/SECURITY_ANALYTICS_AWS_CLOUDTRAIL_ML_MODEL/dashboard.git
cd dashboard
pip install -r requirements.txt
```

## 2. AWS Configuration
```bash
aws configure
```
When prompted:
```
AWS Access Key ID [None]: <your-access-key>
AWS Secret Access Key [None]: <your-secret-access-key>
Default region name [None]: us-east-1
Default output format [None]: json
```

Ensure the IAM user or role has permission to read from the S3 bucket specified in the configuration.

## 3. Running the Dashboard
```bash
streamlit run dashboard.py
```

✅ **Docker Integration Summary**
- Docker is used to **containerize the TensorFlow LSTM model**
- Image is stored in **Amazon ECR**
- AWS Lambda executes the **containerized inference function**
- Ensures consistent runtime and library versions between local and AWS
