# AWS IAM Threat Detection System using LSTM Model

A production-ready AI-powered threat detection system that monitors AWS CloudTrail events in real-time to detect malicious IAM activities using deep learning and context-aware analysis.

## 🎯 Project Overview

This system provides **real-time threat detection** for AWS environments by:
- **Direct CloudTrail API integration** for live event monitoring
- **LSTM neural network** analysis for pattern recognition
- **Context-aware intelligence** to recognize false positives
- **Automated S3 storage** for audit trails and compliance

## 🏗️ Project System Architecture

```
AWS CloudTrail API → Real-time Event Processing → LSTM Model → Security Analysis → S3 Storage
```

## 🚀 Quick Start Guide

### 1. Prerequisites (IMPORTANT!!!)
```bash
# Required software
Python 3.8+
AWS CLI configured with appropriate permissions
TensorFlow 2.x
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

### 2. AWS Setup
```bash
# Ensure AWS credentials are configured
aws configure

# Verify CloudTrail access
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity --max-items 1

# Create S3 bucket for results (optional)
aws s3 mb s3://your-threat-detection-bucket
```

### 3. Running Threat Detection
```bash
# Run real-time threat analysis (default: 7 days)
python threat_detector.py

# Analyze specific time range
python threat_detector.py --days 1
OR
python threat_detector.py --days 0.2

# Use custom configuration
python threat_detector.py --config custom_config.json
```

## 📊 Attack Test Cases

### **Privilege Escalation Detection ✅**
```bash
# Commands tested:
aws iam create-user --user-name malicious-user
aws iam create-access-key --user-name malicious-user
aws iam attach-user-policy --user-name malicious-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### **Lateral Movement Detection ✅**
```bash
# Commands tested:
aws iam create-role --role-name lateral-role-1 --assume-role-policy-document file://trust-policy.json
aws iam attach-role-policy --role-name lateral-role-1 --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess
```

### **Data Exfiltration ✅**
```bash
# Commands tested:
aws iam create-user --user-name data-exfil-user
aws iam create-access-key --user-name data-exfil-user
aws iam create-access-key --user-name data-exfil-user  # Second key
aws iam attach-user-policy --user-name data-exfil-user --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

### **Reconnaissance Testing ⚠️**
```bash
# Commands tested:
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
