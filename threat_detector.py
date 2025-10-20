#!/usr/bin/env python3
"""
IAM Threat Detection System
Scalable, configurable, and comprehensive logging
"""

import boto3
import json
import numpy as np
from datetime import datetime, timedelta
import time
import argparse
import os
import pickle
from typing import List, Dict, Any

# ML/AI imports for trained model
try:
    import tensorflow as tf
    from tensorflow import keras
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: TensorFlow not available. Using fallback rule-based detection.")

class RobustThreatDetector:
    def __init__(self, config_file=None):
        """Initialize with optional configuration file"""
        self.load_config(config_file)
        self.cloudtrail = boto3.client('cloudtrail', region_name=self.config['aws_region'])
        self.sts = boto3.client('sts', region_name=self.config['aws_region'])
        self.s3 = boto3.client('s3', region_name=self.config['aws_region'])
        self.account_info = self.get_account_info()

        # Load trained ML model
        self.load_trained_model()

        # Create output directory
        os.makedirs(self.config['output_dir'], exist_ok=True)

    def load_config(self, config_file=None):
        """Load configuration with defaults"""
        default_config = {
            'time_range_days': 7,  # Default to 7 days instead of 1
            'max_events_per_request': 50,
            'batch_size': 1000,
            'threat_threshold': 0.88,
            'aws_region': 'us-east-1',
            'output_dir': 'threat_analysis_output',
            'event_sources': ['iam.amazonaws.com', 'sts.amazonaws.com', 'ec2.amazonaws.com'],
            'detailed_logging': True,
            'save_all_events': True,
            's3_bucket': 'lstm-model-output',
            'upload_to_s3': True
        }

        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)

        self.config = default_config
        self.threshold = self.config['threat_threshold']
        self.label_classes = ["Normal", "Privilege_Escalation", "Lateral_Movement", "Data_Exfiltration", "Reconnaissance"]

    def get_account_info(self):
        """Get AWS account information"""
        try:
            identity = self.sts.get_caller_identity()
            return {
                'account_id': identity.get('Account'),
                'user_arn': identity.get('Arn'),
                'user_id': identity.get('UserId')
            }
        except Exception as e:
            return {'error': str(e)}

    def load_trained_model(self):
        """Load the trained LSTM model and associated files"""
        self.use_trained_model = False

        if not ML_AVAILABLE:
            print("TensorFlow not available - using rule-based detection")
            return

        try:
            # Load the trained LSTM model
            model_path = 'iam_threat_production_model.h5'
            if os.path.exists(model_path):
                self.trained_model = keras.models.load_model(model_path)
                print(f"[OK] Loaded trained LSTM model: {model_path}")
            else:
                print(f"[ERROR] Model file not found: {model_path}")
                return

            # Load label encoder
            encoder_path = 'production_label_encoder.pkl'
            if os.path.exists(encoder_path):
                with open(encoder_path, 'rb') as f:
                    self.label_encoder = pickle.load(f)
                print(f"[OK] Loaded label encoder: {encoder_path}")
            else:
                print(f"[ERROR] Label encoder not found: {encoder_path}")
                return

            # Load production threshold
            threshold_path = 'production_threshold.pkl'
            if os.path.exists(threshold_path):
                with open(threshold_path, 'rb') as f:
                    self.trained_threshold = pickle.load(f)
                print(f"[OK] Loaded production threshold: {self.trained_threshold}")
            else:
                print(f"[ERROR] Threshold file not found: {threshold_path}")
                self.trained_threshold = 0.88  # Default

            # Load metadata
            metadata_path = 'production_metadata.pkl'
            if os.path.exists(metadata_path):
                with open(metadata_path, 'rb') as f:
                    self.model_metadata = pickle.load(f)
                print(f"[OK] Loaded model metadata")
            else:
                print(f"[WARNING] Metadata file not found, using defaults")
                self.model_metadata = {}

            self.use_trained_model = True
            print("ML/AI MODE: Using trained LSTM neural network for predictions")

        except Exception as e:
            print(f"[ERROR] Error loading trained model: {e}")
            print("Falling back to rule-based detection")
            self.use_trained_model = False

    def fetch_events_batch(self, start_time, end_time, event_source, next_token=None):
        """Fetch events in batches with pagination and full event details"""
        try:
            params = {
                'LookupAttributes': [
                    {
                        'AttributeKey': 'EventSource',
                        'AttributeValue': event_source
                    }
                ],
                'StartTime': start_time,
                'EndTime': end_time,
                'MaxResults': self.config['max_events_per_request']
            }

            if next_token:
                params['NextToken'] = next_token

            # Get basic events first
            response = self.cloudtrail.lookup_events(**params)
            basic_events = response.get('Events', [])
            next_token = response.get('NextToken')

            # Enhance events with full details
            enhanced_events = []
            for event in basic_events:
                enhanced_event = self.get_full_event_details(event)
                enhanced_events.append(enhanced_event)

            return enhanced_events, next_token

        except Exception as e:
            print(f"Error fetching {event_source} events: {e}")
            return [], None

    def get_full_event_details(self, basic_event):
        """Get full event details including MFA and session information"""
        try:
            # Try to get the full event record using CloudTrail's event ID
            event_id = basic_event.get('EventId')

            if not event_id:
                return basic_event

            # Use CloudTrail insights or detailed event lookup
            # Note: CloudTrail lookup_events already returns most details in CloudTrailEvent
            cloud_trail_event = basic_event.get('CloudTrailEvent')

            if cloud_trail_event:
                # Parse the JSON string to get detailed event data
                import json
                try:
                    detailed_event = json.loads(cloud_trail_event)

                    # Merge the detailed information with basic event
                    enhanced_event = basic_event.copy()

                    # Add detailed user identity information
                    if 'userIdentity' in detailed_event:
                        enhanced_event['UserIdentity'] = detailed_event['userIdentity']

                    # Add session information
                    if 'sessionCredentialFromConsole' in detailed_event:
                        enhanced_event['sessionCredentialFromConsole'] = detailed_event['sessionCredentialFromConsole']

                    # Add user agent information
                    if 'userAgent' in detailed_event:
                        enhanced_event['userAgent'] = detailed_event['userAgent']

                    # Add source IP information
                    if 'sourceIPAddress' in detailed_event:
                        enhanced_event['sourceIPAddress'] = detailed_event['sourceIPAddress']

                    # Add request parameters
                    if 'requestParameters' in detailed_event:
                        enhanced_event['requestParameters'] = detailed_event['requestParameters']

                    # Add response elements
                    if 'responseElements' in detailed_event:
                        enhanced_event['responseElements'] = detailed_event['responseElements']

                    return enhanced_event

                except json.JSONDecodeError as e:
                    print(f"[WARNING] Could not parse CloudTrailEvent JSON for {event_id}: {e}")
                    return basic_event
            else:
                print(f"[WARNING] No CloudTrailEvent data for {event_id}")
                return basic_event

        except Exception as e:
            print(f"[WARNING] Error getting full event details for {basic_event.get('EventId', 'unknown')}: {e}")
            return basic_event

    def fetch_all_events(self, days_back=None):
        """Fetch all events across specified time range"""
        days_back = days_back or self.config['time_range_days']
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days_back)

        print(f"Fetching events from {start_time.strftime('%Y-%m-%d')} to {end_time.strftime('%Y-%m-%d')} ({days_back} days)")

        all_events = []
        total_events_by_source = {}

        for event_source in self.config['event_sources']:
            print(f"Fetching {event_source} events...")
            source_events = []
            next_token = None

            while True:
                events, next_token = self.fetch_events_batch(start_time, end_time, event_source, next_token)
                source_events.extend(events)

                if not next_token or len(source_events) >= self.config['batch_size']:
                    break

                time.sleep(0.1)  # Rate limiting

            total_events_by_source[event_source] = len(source_events)
            all_events.extend(source_events)
            print(f"Found {len(source_events)} events from {event_source}")

        # Sort by timestamp
        all_events.sort(key=lambda x: x['EventTime'])

        print(f"Total events collected: {len(all_events)}")
        return all_events, total_events_by_source

    def extract_enhanced_features(self, event):
        """Extract comprehensive features from CloudTrail event"""
        features = {}

        # Time-based features
        event_time = event.get('EventTime', datetime.now())
        features['event_time_hour'] = int(event_time.hour)
        features['event_time_day_of_week'] = event_time.weekday()
        features['event_time_is_weekend'] = 1 if event_time.weekday() >= 5 else 0

        # Basic event info
        features['event_source'] = event.get('EventSource', '')
        event_name = event.get('EventName', '')
        features['event_name'] = event_name
        features['aws_region'] = event.get('AwsRegion', '')
        features['source_ip'] = event.get('SourceIPAddress', '')

        # User identity features
        user_identity = event.get('UserIdentity', {})
        features['user_type'] = user_identity.get('type', '')
        features['user_name'] = user_identity.get('userName', '')
        features['is_root'] = 1 if user_identity.get('type') == 'Root' else 0
        features['is_iam_user'] = 1 if user_identity.get('type') == 'IAMUser' else 0
        features['is_assumed_role'] = 1 if user_identity.get('type') == 'AssumedRole' else 0

        # Error handling
        error_code = event.get('ErrorCode', '')
        features['has_error'] = 1 if error_code else 0
        features['is_access_denied'] = 1 if 'AccessDenied' in error_code else 0

        # Enhanced malicious activity detection based on EventName patterns
        role_events = ['CreateRole', 'DeleteRole', 'AttachRolePolicy', 'DetachRolePolicy', 'PutRolePolicy', 'AssumeRole']
        policy_events = ['CreatePolicy', 'AttachUserPolicy', 'AttachGroupPolicy', 'AttachRolePolicy', 'PutUserPolicy', 'PutGroupPolicy', 'PutRolePolicy']
        user_events = ['CreateUser', 'DeleteUser', 'AddUserToGroup', 'CreateAccessKey', 'CreateLoginProfile']
        admin_events = ['AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy']

        features['is_role_operation'] = 1 if event_name in role_events else 0
        features['is_policy_operation'] = 1 if event_name in policy_events else 0
        features['is_user_operation'] = 1 if event_name in user_events else 0
        features['is_admin_operation'] = 1 if event_name in admin_events else 0

        # Request parameters analysis (secondary check)
        request_params = event.get('RequestParameters', {})
        if request_params:
            features['request_param_count'] = len(request_params)
            features['has_role_name'] = 1 if any('role' in str(k).lower() for k in request_params.keys()) else 0
            features['has_policy'] = 1 if any('policy' in str(k).lower() for k in request_params.keys()) else 0
            features['has_user_name'] = 1 if any('user' in str(k).lower() for k in request_params.keys()) else 0

            # Check for admin policy ARN in parameters
            admin_policy_indicators = ['AdministratorAccess', 'PowerUserAccess', 'IAMFullAccess', ':policy/Admin']
            features['has_admin_policy'] = 1 if any(indicator in str(request_params) for indicator in admin_policy_indicators) else 0
        else:
            features['request_param_count'] = 0
            features['has_role_name'] = 0
            features['has_policy'] = 0
            features['has_user_name'] = 0
            features['has_admin_policy'] = 0

        # Combine EventName-based and parameter-based detection
        features['has_role_activity'] = max(features['is_role_operation'], features['has_role_name'])
        features['has_policy_activity'] = max(features['is_policy_operation'], features['has_policy'])
        features['has_privilege_escalation'] = max(features['is_admin_operation'], features['has_admin_policy'])

        # Resources
        resources = event.get('Resources', [])
        features['resource_count'] = len(resources)

        # Response elements
        response_elements = event.get('ResponseElements', {})
        features['has_response_elements'] = 1 if response_elements else 0

        return features

    def create_advanced_sequence(self, events):
        """Create advanced feature sequences for ML analysis"""
        if len(events) == 0:
            return []

        # Use more events for better pattern detection
        sequence_length = min(50, len(events))
        feature_vectors = []

        for event in events[-sequence_length:]:
            features = self.extract_enhanced_features(event)

            # Convert to normalized numerical vector with enhanced malicious detection
            vector = [
                features['event_time_hour'] / 24.0,
                features['event_time_day_of_week'] / 7.0,
                features['event_time_is_weekend'],
                features['has_error'],
                features['is_access_denied'],
                features['request_param_count'] / 20.0,  # Normalize to reasonable range
                features['has_role_activity'],  # Enhanced role detection
                features['has_policy_activity'],  # Enhanced policy detection
                features['has_privilege_escalation'],  # Enhanced admin operation detection
                features['resource_count'] / 10.0,
                features['is_root'],
                features['is_iam_user'],
                features['is_assumed_role'],
                features['has_response_elements'],
                features['is_role_operation'],  # Direct EventName pattern detection
                features['is_policy_operation'],
                features['is_user_operation'],
                features['is_admin_operation'],
                features['has_admin_policy']  # Admin policy detection
            ]

            # Pad to fixed length
            while len(vector) < 20:
                vector.append(0.0)

            feature_vectors.append(vector[:20])

        # Pad sequence to fixed length
        while len(feature_vectors) < 50:
            feature_vectors.append([0.5] * 20)

        return feature_vectors

    def create_lstm_sequence(self, events):
        """Create LSTM-compatible sequence for trained model"""
        if not self.use_trained_model or len(events) == 0:
            return None

        try:
            # Use the same feature extraction as original training
            feature_vectors = []

            # Take last 20 events (same as training)
            sequence_length = 20
            recent_events = events[-sequence_length:] if len(events) >= sequence_length else events

            for event in recent_events:
                # Extract basic features (compatible with original training)
                event_time = event.get('EventTime', datetime.now())
                hour = event_time.hour if hasattr(event_time, 'hour') else 12

                # Basic feature vector (same as original LSTM training)
                features = [
                    hour / 24.0,  # Normalized hour
                    1 if event.get('ErrorCode') else 0,  # Has error
                    len(event.get('RequestParameters', {})) / 10.0,  # Request params
                    1 if 'role' in str(event.get('RequestParameters', {})).lower() else 0,  # Role operation
                    1 if 'policy' in str(event.get('RequestParameters', {})).lower() else 0,  # Policy operation
                    len(event.get('Resources', [])) / 5.0  # Resource count
                ]

                # Pad/truncate to fixed size
                while len(features) < 20:
                    features.append(0.0)
                features = features[:20]

                feature_vectors.append(features)

            # Pad sequence to fixed length
            while len(feature_vectors) < sequence_length:
                feature_vectors.append([0.5] * 20)

            # Convert to numpy array with correct shape for LSTM
            sequence = np.array(feature_vectors)
            sequence = sequence.reshape(1, sequence_length, 20)  # (batch_size, timesteps, features)

            return sequence

        except Exception as e:
            print(f"Error creating LSTM sequence: {e}")
            return None

    def analyze_event_context(self, events):
        """Analyze events for trust and risk signals"""
        context = {
            'trust_signals': [],
            'risk_signals': [],
            'trust_score': 0,
            'risk_score': 0,
            'business_hours_activity': 0,
            'off_hours_activity': 0,
            'mfa_authenticated_events': 0,
            'cloudshell_events': 0
        }

        for event in events:
            event_time = event.get('EventTime', datetime.now())
            hour = event_time.hour if hasattr(event_time, 'hour') else 12

            # Trust signals analysis
            user_identity = event.get('UserIdentity', {})
            session_context = user_identity.get('sessionContext', {})
            attributes = session_context.get('attributes', {})
            user_agent = event.get('userAgent', '')
            source_ip = event.get('sourceIPAddress', '')

            # MFA authentication check (comprehensive field checking)
            mfa_authenticated = False

            # Check in session context attributes
            if attributes and attributes.get('mfaAuthenticated') == 'true':
                mfa_authenticated = True
            # Check in direct event field
            elif event.get('mfaAuthenticated') == 'true':
                mfa_authenticated = True
            # Check in user identity (enhanced event structure)
            elif user_identity and isinstance(user_identity, dict):
                session_context = user_identity.get('sessionContext', {})
                if isinstance(session_context, dict):
                    attributes = session_context.get('attributes', {})
                    if isinstance(attributes, dict) and attributes.get('mfaAuthenticated') == 'true':
                        mfa_authenticated = True
            # Check in string representation as fallback
            elif 'mfaAuthenticated":true' in str(event) or 'mfaAuthenticated":"true"' in str(event):
                mfa_authenticated = True

            if mfa_authenticated:
                context['mfa_authenticated_events'] += 1

            # CloudShell/Console check (comprehensive detection)
            is_cloudshell = False
            is_console = False

            # Check user agent field
            if user_agent and isinstance(user_agent, str):
                if 'CloudShell' in user_agent or 'aws-cli' in user_agent or 'CloudShell' in user_agent:
                    is_cloudshell = True

            # Check session credential source
            if event.get('sessionCredentialFromConsole') == 'true':
                is_console = True
            elif event.get('sessionCredentialFromConsole') is True:
                is_console = True

            # Additional check for console indicators in user identity
            if user_identity and isinstance(user_identity, dict):
                if user_identity.get('type') == 'IAMUser' and session_context:
                    session_issuer = session_context.get('sessionIssuer', {})
                    if session_issuer and session_issuer.get('type') == 'Role':
                        # This might indicate console access
                        is_console = True

            if is_cloudshell or is_console:
                context['cloudshell_events'] += 1

            # Business hours analysis (9 AM - 6 PM UTC)
            if 9 <= hour <= 18:
                context['business_hours_activity'] += 1
            else:
                context['off_hours_activity'] += 1

            # Trust signals
            if mfa_authenticated:
                if 'MFA authenticated' not in context['trust_signals']:
                    context['trust_signals'].append('MFA authenticated')
                context['trust_score'] += 0.3

            if is_cloudshell or is_console:
                if 'CloudShell/Console source' not in context['trust_signals']:
                    context['trust_signals'].append('CloudShell/Console source')
                context['trust_score'] += 0.2

            if 9 <= hour <= 18:
                context['trust_score'] += 0.1
            elif hour < 6 or hour > 22:  # Very off hours
                if 'Very off-hours activity' not in context['risk_signals']:
                    context['risk_signals'].append('Very off-hours activity')
                context['risk_score'] += 0.3

            # Risk signals
            error_code = event.get('ErrorCode', '')
            if 'AccessDenied' in error_code:
                if 'Access denied attempts' not in context['risk_signals']:
                    context['risk_signals'].append('Access denied attempts')
                context['risk_score'] += 0.4

            if not mfa_authenticated and user_identity.get('type') == 'IAMUser':
                if 'No MFA authentication' not in context['risk_signals']:
                    context['risk_signals'].append('No MFA authentication')
                context['risk_score'] += 0.2

            # External IP risk (simplified check)
            if source_ip and not any(source_ip.startswith(prefix) for prefix in ['10.', '172.', '192.168.', '127.']):
                if 'External IP source' not in context['risk_signals']:
                    context['risk_signals'].append('External IP source')
                context['risk_score'] += 0.1

        # Add business hours context
        total_events = len(events)
        if total_events > 0:
            business_hours_ratio = context['business_hours_activity'] / total_events
            if business_hours_ratio > 0.7:
                context['trust_signals'].append('Primarily business hours activity')
                context['trust_score'] += 0.2

            mfa_ratio = context['mfa_authenticated_events'] / total_events
            if mfa_ratio > 0.5:
                context['trust_signals'].append('High MFA usage')
                context['trust_score'] += 0.3

        return context

    def apply_context_adjustment(self, raw_confidence, context_analysis, predicted_class):
        """Apply context-aware adjustments to confidence score"""
        adjusted_confidence = raw_confidence

        # For privilege escalation events (most common false positives)
        if predicted_class == 1:  # Privilege_Escalation class
            # Strong trust signals reduce confidence
            trust_adjustment = min(context_analysis['trust_score'] * 0.3, 0.4)
            adjusted_confidence = max(0.1, raw_confidence - trust_adjustment)

            # But risk signals increase it
            risk_adjustment = min(context_analysis['risk_score'] * 0.2, 0.3)
            adjusted_confidence = min(1.0, adjusted_confidence + risk_adjustment)

        # For all other threat types, apply lighter adjustments
        else:
            trust_adjustment = min(context_analysis['trust_score'] * 0.15, 0.2)
            adjusted_confidence = max(0.1, raw_confidence - trust_adjustment)

            risk_adjustment = min(context_analysis['risk_score'] * 0.15, 0.2)
            adjusted_confidence = min(1.0, adjusted_confidence + risk_adjustment)

        return adjusted_confidence

    def predict_with_lstm(self, events, malicious_event_breakdown):
        """Make predictions using the trained LSTM model with enhanced context awareness"""
        try:
            print("[AI] Using trained LSTM neural network for prediction...")

            # Create LSTM-compatible sequence
            lstm_sequence = self.create_lstm_sequence(events)
            if lstm_sequence is None:
                print("[ERROR] Could not create LSTM sequence")
                return None

            # Make prediction with trained model
            prediction_probabilities = self.trained_model.predict(lstm_sequence, verbose=0)
            predicted_class = np.argmax(prediction_probabilities[0])
            raw_confidence = float(np.max(prediction_probabilities[0]))

            # Apply context-aware confidence adjustment
            context_analysis = self.analyze_event_context(events)
            adjusted_confidence = self.apply_context_adjustment(raw_confidence, context_analysis, predicted_class)

            # Get threat type from label encoder
            try:
                threat_type = self.label_encoder.inverse_transform([predicted_class])[0]
            except:
                # Fallback to default classes
                threat_classes = ["Normal", "Privilege_Escalation", "Lateral_Movement", "Data_Exfiltration", "Reconnaissance"]
                threat_type = threat_classes[predicted_class] if predicted_class < len(threat_classes) else "Unknown"

            # Apply trained threshold to adjusted confidence
            is_threat = adjusted_confidence > self.trained_threshold

            # Risk level based on adjusted confidence
            if adjusted_confidence > 0.9:
                risk_level = "CRITICAL"
            elif adjusted_confidence > 0.8:
                risk_level = "HIGH"
            elif adjusted_confidence > 0.7:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            # Enhanced risk factors with context awareness
            risk_factors = []
            if malicious_event_breakdown['total_malicious'] > 0:
                risk_factors.append(f"LSTM detected {malicious_event_breakdown['total_malicious']} suspicious events")
            if adjusted_confidence > 0.8:
                risk_factors.append("High confidence LSTM prediction")
            if predicted_class > 0:
                risk_factors.append("Neural network identified non-normal pattern")

            # Add context-specific risk factors
            if context_analysis['trust_signals']:
                risk_factors.append(f"Trust signals present: {', '.join(context_analysis['trust_signals'])}")
            if context_analysis['risk_signals']:
                risk_factors.append(f"Risk signals detected: {', '.join(context_analysis['risk_signals'])}")

            print(f"[AI] LSTM Prediction: {threat_type} (raw: {raw_confidence:.3f}, adjusted: {adjusted_confidence:.3f})")

            return {
                'threat_type': threat_type,
                'confidence': round(float(adjusted_confidence), 3),
                'raw_confidence': round(float(raw_confidence), 3),
                'is_threat': bool(is_threat),
                'risk_level': risk_level,
                'predicted_class': int(predicted_class),
                'threshold_used': float(self.trained_threshold),
                'risk_factors': risk_factors,
                'context_analysis': context_analysis,
                'malicious_events_breakdown': malicious_event_breakdown,
                'model_type': 'Context-Aware LSTM Neural Network',
                'prediction_method': 'Deep Learning + Context Analysis',
                'sequence_stats': {
                    'lstm_sequence_shape': str(lstm_sequence.shape),
                    'events_processed': len(events),
                    'raw_model_confidence': round(float(raw_confidence), 3),
                    'context_adjusted_confidence': round(float(adjusted_confidence), 3)
                },
                'events_analyzed': len(events)
            }

        except Exception as e:
            print(f"[ERROR] Error in LSTM prediction: {e}")
            return None

    def count_malicious_events(self, events):
        """Count and categorize individual malicious events"""
        malicious_events = {
            'privilege_escalation': [],
            'reconnaissance': [],
            'lateral_movement': [],
            'data_exfiltration': [],
            'suspicious_access': [],
            'total_malicious': 0,
            'total_events': len(events)
        }

        # Define malicious event patterns
        privilege_escalation_events = [
            'CreateRole', 'DeleteRole', 'AttachRolePolicy', 'AttachUserPolicy', 'AttachGroupPolicy',
            'PutRolePolicy', 'PutUserPolicy', 'PutGroupPolicy', 'CreateUser', 'CreateAccessKey',
            'CreateLoginProfile', 'AddUserToGroup'
        ]

        reconnaissance_events = [
            'ListUsers', 'ListRoles', 'ListPolicies', 'ListGroups', 'GetAccountSummary',
            'GetUser', 'GetRole', 'GetPolicy', 'ListAttachedUserPolicies', 'ListAttachedRolePolicies'
        ]

        for event in events:
            event_name = event.get('EventName', '')
            error_code = event.get('ErrorCode', '')
            is_malicious = False

            # Check for privilege escalation with context awareness
            if event_name in privilege_escalation_events:
                # Apply context-based filtering for common events
                should_flag = True

                # For CreateUser events, apply stricter criteria
                if event_name == 'CreateUser':
                    user_identity = event.get('UserIdentity', {})
                    session_context = user_identity.get('sessionContext', {})
                    attributes = session_context.get('attributes', {})
                    user_agent = event.get('userAgent', '')

                    # Check for trust signals
                    has_mfa = attributes.get('mfaAuthenticated') == 'true'
                    has_console = event.get('sessionCredentialFromConsole') == 'true'
                    has_cloudshell = 'CloudShell' in user_agent or 'aws-cli' in user_agent

                    # If CreateUser has strong trust signals, don't flag as malicious
                    if has_mfa and (has_console or has_cloudshell):
                        should_flag = False

                if should_flag:
                    malicious_events['privilege_escalation'].append({
                        'EventName': event_name,
                        'EventTime': event.get('EventTime', '').isoformat() if hasattr(event.get('EventTime', ''), 'isoformat') else str(event.get('EventTime', '')),
                        'EventId': event.get('EventId', ''),
                        'ErrorCode': error_code,
                        'Username': event.get('Username', 'Unknown')
                    })
                    is_malicious = True

            # Check for reconnaissance (especially with errors)
            elif event_name in reconnaissance_events and error_code:
                malicious_events['reconnaissance'].append({
                    'EventName': event_name,
                    'EventTime': event.get('EventTime', '').isoformat() if hasattr(event.get('EventTime', ''), 'isoformat') else str(event.get('EventTime', '')),
                    'EventId': event.get('EventId', ''),
                    'ErrorCode': error_code,
                    'Username': event.get('Username', 'Unknown')
                })
                is_malicious = True

            # Check for access denied events (potential reconnaissance)
            elif 'AccessDenied' in error_code:
                malicious_events['suspicious_access'].append({
                    'EventName': event_name,
                    'EventTime': event.get('EventTime', '').isoformat() if hasattr(event.get('EventTime', ''), 'isoformat') else str(event.get('EventTime', '')),
                    'EventId': event.get('EventId', ''),
                    'ErrorCode': error_code,
                    'Username': event.get('Username', 'Unknown')
                })
                is_malicious = True

            # Check for root account activity
            user_identity = event.get('UserIdentity', {})
            if user_identity.get('type') == 'Root':
                malicious_events['suspicious_access'].append({
                    'EventName': event_name,
                    'EventTime': event.get('EventTime', '').isoformat() if hasattr(event.get('EventTime', ''), 'isoformat') else str(event.get('EventTime', '')),
                    'EventId': event.get('EventId', ''),
                    'ErrorCode': error_code,
                    'Username': 'ROOT',
                    'Type': 'Root Account Activity'
                })
                is_malicious = True

            if is_malicious:
                malicious_events['total_malicious'] += 1

        # Calculate percentages
        malicious_events['malicious_percentage'] = round(
            (malicious_events['total_malicious'] / malicious_events['total_events']) * 100, 2
        ) if malicious_events['total_events'] > 0 else 0

        return malicious_events

    def analyze_threat_patterns(self, sequence, events):
        """Enhanced threat pattern analysis using trained LSTM model or fallback rules"""
        if not sequence and not events:
            return self.create_default_prediction("No events to analyze")

        # Count individual malicious events for detailed breakdown
        malicious_event_breakdown = self.count_malicious_events(events)

        # Try to use trained LSTM model first
        if self.use_trained_model:
            lstm_prediction = self.predict_with_lstm(events, malicious_event_breakdown)
            if lstm_prediction:
                return lstm_prediction

        # Fallback to rule-based analysis
        print("Using fallback rule-based analysis")
        if not sequence:
            return self.create_default_prediction("No sequence data for rule-based analysis")

        sequence = np.array(sequence)

        # Calculate comprehensive statistics
        sequence_mean = np.mean(sequence)
        sequence_std = np.std(sequence)
        sequence_max = np.max(sequence)
        sequence_min = np.min(sequence)

        # Advanced pattern detection with enhanced indices
        error_rate = np.mean(sequence[:, 3])  # Error column
        access_denied_rate = np.mean(sequence[:, 4])  # Access denied column
        role_activity = np.mean(sequence[:, 6])  # Enhanced role activity
        policy_activity = np.mean(sequence[:, 7])  # Enhanced policy activity
        privilege_escalation = np.mean(sequence[:, 8])  # Enhanced privilege escalation
        root_activity = np.mean(sequence[:, 10])  # Root activity
        admin_operations = np.mean(sequence[:, 17])  # Admin operations
        admin_policy_activity = np.mean(sequence[:, 18])  # Admin policy attachment

        # Multi-factor threat classification with enhanced detection
        confidence = 0.5
        predicted_class = 0
        risk_factors = []

        # CRITICAL: Enhanced privilege escalation detection
        if admin_policy_activity > 0.0 or privilege_escalation > 0.0:
            predicted_class = 1  # Privilege_Escalation
            confidence = 0.95
            risk_factors.append("Admin policy attachment or privilege escalation detected")
        elif root_activity > 0.3:
            predicted_class = 1  # Privilege_Escalation
            confidence = 0.90
            risk_factors.append("High root account activity")
        elif role_activity > 0.1 and policy_activity > 0.1:
            predicted_class = 1  # Privilege_Escalation
            confidence = 0.85
            risk_factors.append("Role creation combined with policy operations")
        elif access_denied_rate > 0.4:
            predicted_class = 4  # Reconnaissance
            confidence = 0.85
            risk_factors.append("High access denied rate - potential reconnaissance")
        elif error_rate > 0.3 and (role_activity > 0.0 or policy_activity > 0.0):
            predicted_class = 1  # Privilege_Escalation
            confidence = 0.80
            risk_factors.append("High error rate with privilege operations")
        elif admin_operations > 0.0:
            predicted_class = 1  # Privilege_Escalation
            confidence = 0.75
            risk_factors.append("Administrative operations detected")
        elif sequence_std > 0.4 and sequence_max > 0.8:
            predicted_class = 2  # Lateral_Movement
            confidence = 0.75
            risk_factors.append("High variance in activity patterns")
        elif role_activity > 0.5 or policy_activity > 0.5:
            predicted_class = 3  # Data_Exfiltration
            confidence = 0.70
            risk_factors.append("High privilege operation activity")
        elif sequence_mean > 0.6:
            predicted_class = 3  # Data_Exfiltration
            confidence = 0.65
            risk_factors.append("Sustained high activity levels")

        threat_type = self.label_classes[predicted_class]
        is_threat = confidence > self.threshold

        # Risk level
        if confidence > 0.9:
            risk_level = "CRITICAL"
        elif confidence > 0.8:
            risk_level = "HIGH"
        elif confidence > 0.7:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            'threat_type': threat_type,
            'confidence': round(confidence, 3),
            'is_threat': is_threat,
            'risk_level': risk_level,
            'predicted_class': predicted_class,
            'threshold_used': self.threshold,
            'risk_factors': risk_factors,
            'malicious_events_breakdown': malicious_event_breakdown,
            'sequence_stats': {
                'mean': round(sequence_mean, 3),
                'std': round(sequence_std, 3),
                'max': round(sequence_max, 3),
                'min': round(sequence_min, 3),
                'error_rate': round(error_rate, 3),
                'access_denied_rate': round(access_denied_rate, 3),
                'role_activity_rate': round(role_activity, 3),
                'policy_activity_rate': round(policy_activity, 3),
                'privilege_escalation_rate': round(privilege_escalation, 3),
                'root_activity_rate': round(root_activity, 3),
                'admin_operations_rate': round(admin_operations, 3),
                'admin_policy_activity_rate': round(admin_policy_activity, 3)
            },
            'events_analyzed': len(events)
        }

    def create_default_prediction(self, reason):
        """Create default prediction for edge cases"""
        return {
            'threat_type': 'Normal',
            'confidence': 0.5,
            'is_threat': False,
            'risk_level': 'LOW',
            'predicted_class': 0,
            'threshold_used': self.threshold,
            'risk_factors': [],
            'sequence_stats': {},
            'events_analyzed': 0,
            'reason': reason
        }

    def upload_to_s3(self, local_file_path, s3_key):
        """Upload file to S3 bucket with error handling"""
        if not self.config.get('upload_to_s3', False):
            return False

        try:
            bucket_name = self.config['s3_bucket']
            self.s3.upload_file(local_file_path, bucket_name, s3_key)
            print(f"[S3] Uploaded: s3://{bucket_name}/{s3_key}")
            return True
        except Exception as e:
            print(f"[S3] Upload failed: {e}")
            return False

    def save_comprehensive_analysis(self, events, prediction, events_by_source):
        """Save comprehensive analysis to JSON files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Main analysis report
        analysis_report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'account_info': self.account_info,
            'configuration': self.config,
            'summary': {
                'total_events': len(events),
                'events_by_source': events_by_source,
                'time_range': {
                    'days_analyzed': self.config['time_range_days'],
                    'start_time': (datetime.now() - timedelta(days=self.config['time_range_days'])).isoformat(),
                    'end_time': datetime.now().isoformat()
                }
            },
            'threat_analysis': prediction
        }

        report_file = os.path.join(self.config['output_dir'], f'threat_analysis_report_{timestamp}.json')
        with open(report_file, 'w') as f:
            json.dump(analysis_report, f, indent=2)

        # Upload analysis report to S3
        s3_report_key = f"analysis-reports/threat_analysis_report_{timestamp}.json"
        self.upload_to_s3(report_file, s3_report_key)

        # Save all events if configured
        if self.config['save_all_events'] and events:
            events_data = {
                'metadata': {
                    'total_events': len(events),
                    'collection_timestamp': datetime.now().isoformat(),
                    'account_info': self.account_info
                },
                'events': [
                    {
                        'EventId': event.get('EventId'),
                        'EventTime': event['EventTime'].isoformat(),
                        'EventName': event['EventName'],
                        'EventSource': event.get('EventSource'),
                        'Username': event.get('Username'),
                        'UserIdentity': event.get('UserIdentity'),
                        'SourceIPAddress': event.get('SourceIPAddress'),
                        'AwsRegion': event.get('AwsRegion'),
                        'ErrorCode': event.get('ErrorCode'),
                        'RequestParameters': event.get('RequestParameters'),
                        'ResponseElements': event.get('ResponseElements'),
                        'Resources': event.get('Resources')
                    }
                    for event in events
                ]
            }

            events_file = os.path.join(self.config['output_dir'], f'all_events_{timestamp}.json')
            with open(events_file, 'w') as f:
                json.dump(events_data, f, indent=2)

            # Upload events file to S3
            s3_events_key = f"all-events/all_events_{timestamp}.json"
            self.upload_to_s3(events_file, s3_events_key)

        return report_file, events_file if self.config['save_all_events'] else None

    def run_analysis(self, days_back=None):
        """Run comprehensive threat analysis"""
        print("="*80)
        print("IAM THREAT DETECTION SYSTEM")
        print("="*80)

        # Fetch all events
        events, events_by_source = self.fetch_all_events(days_back)

        if not events:
            print("No events found in the specified time range")
            prediction = self.create_default_prediction("No events found")
        else:
            # Analyze for threats
            sequence = self.create_advanced_sequence(events)
            prediction = self.analyze_threat_patterns(sequence, events)

        # Save comprehensive analysis
        report_file, events_file = self.save_comprehensive_analysis(events, prediction, events_by_source)

        # Terminal summary
        print(f"\nANALYSIS SUMMARY:")
        print(f"Time Range: {self.config['time_range_days']} days")
        print(f"Total Events: {len(events)}")

        # Malicious event breakdown
        breakdown = prediction['malicious_events_breakdown']
        print(f"Malicious Events: {breakdown['total_malicious']}/{breakdown['total_events']} ({breakdown['malicious_percentage']}%)")

        if breakdown['total_malicious'] > 0:
            print(f"Breakdown:")
            if breakdown['privilege_escalation']:
                print(f"  - Privilege Escalation: {len(breakdown['privilege_escalation'])} events")
            if breakdown['reconnaissance']:
                print(f"  - Reconnaissance: {len(breakdown['reconnaissance'])} events")
            if breakdown['suspicious_access']:
                print(f"  - Suspicious Access: {len(breakdown['suspicious_access'])} events")

        print(f"Threat Type: {prediction['threat_type']}")
        print(f"Confidence: {prediction['confidence']}")
        print(f"Risk Level: {prediction['risk_level']}")
        print(f"Is Threat: {prediction['is_threat']}")

        if prediction['risk_factors']:
            print(f"Risk Factors: {', '.join(prediction['risk_factors'])}")

        print(f"\nOUTPUT FILES:")
        print(f"Analysis Report: {report_file}")
        if events_file:
            print(f"All Events: {events_file}")

        if self.config.get('upload_to_s3', False):
            bucket_name = self.config['s3_bucket']
            timestamp = os.path.basename(report_file).split('_', 2)[2].replace('.json', '')
            print(f"\nS3 UPLOADS:")
            print(f"S3 Analysis Report: s3://{bucket_name}/analysis-reports/threat_analysis_report_{timestamp}.json")
            if events_file:
                print(f"S3 All Events: s3://{bucket_name}/all-events/all_events_{timestamp}.json")

        return prediction, report_file

def main():
    parser = argparse.ArgumentParser(description='IAM Threat Detection')
    parser.add_argument('--days', type=int, default=7, help='Number of days to analyze (default: 7)')
    parser.add_argument('--config', type=str, help='Configuration file path')

    args = parser.parse_args()

    detector = RobustThreatDetector(config_file=args.config)
    prediction, report_file = detector.run_analysis(days_back=args.days)

    print(f"\nAnalysis complete! Check {report_file} for detailed results.")

if __name__ == '__main__':
    main()