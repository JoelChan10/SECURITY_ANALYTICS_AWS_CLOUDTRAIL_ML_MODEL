import json
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import re
import ipaddress
from collections import defaultdict

class CloudTrailProcessor:
    def __init__(self):
        self.label_encoders = {}
        self.scaler = StandardScaler()
        self.user_sessions = defaultdict(list)

    def load_cloudtrail_data(self, filepath):
        """Load and parse CloudTrail JSON data"""
        print(f"Loading CloudTrail data from {filepath}...")

        with open(filepath, 'r') as f:
            data = json.load(f)

        records = data['Records']
        print(f"Loaded {len(records)} CloudTrail records")

        # Convert to DataFrame
        df = pd.DataFrame(records)
        return df

    def extract_basic_features(self, df):
        """Extract basic features from CloudTrail records"""
        print("Extracting basic features...")

        features_df = pd.DataFrame()

        # Basic event information
        features_df['eventTime'] = pd.to_datetime(df['eventTime'])
        features_df['eventName'] = df['eventName']
        features_df['eventSource'] = df['eventSource']
        features_df['eventType'] = df['eventType']
        features_df['awsRegion'] = df['awsRegion']
        features_df['sourceIPAddress'] = df['sourceIPAddress']
        features_df['userAgent'] = df['userAgent']

        # Error information
        features_df['errorCode'] = df['errorCode'].fillna('Success')
        features_df['errorMessage'] = df['errorMessage'].fillna('')
        features_df['isError'] = df['errorCode'].notna().astype(int)

        # User identity information
        features_df['userType'] = df['userIdentity'].apply(
            lambda x: x.get('type', 'Unknown') if isinstance(x, dict) else 'Unknown'
        )
        features_df['userName'] = df['userIdentity'].apply(
            lambda x: x.get('userName', 'Unknown') if isinstance(x, dict) else 'Unknown'
        )
        features_df['accountId'] = df['userIdentity'].apply(
            lambda x: x.get('accountId', 'Unknown') if isinstance(x, dict) else 'Unknown'
        )

        return features_df

    def engineer_advanced_features(self, df):
        """Engineer advanced features for security analysis"""
        print("Engineering advanced features...")

        # Time-based features
        df['hour'] = df['eventTime'].dt.hour
        df['day_of_week'] = df['eventTime'].dt.dayofweek
        df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
        df['is_business_hours'] = ((df['hour'] >= 9) & (df['hour'] <= 17)).astype(int)

        # IP-based features
        df['is_internal_ip'] = df['sourceIPAddress'].apply(self._is_internal_ip)
        df['is_aws_service'] = df['sourceIPAddress'].str.contains('amazonaws.com', na=False).astype(int)

        # Event pattern features
        df['is_read_operation'] = df['eventName'].str.contains('Describe|List|Get', case=False, na=False).astype(int)
        df['is_write_operation'] = df['eventName'].str.contains('Create|Delete|Put|Update|Modify', case=False, na=False).astype(int)
        df['is_high_risk_operation'] = df['eventName'].str.contains('AssumeRole|RunInstances|CreateUser|AttachPolicy', case=False, na=False).astype(int)

        # User agent analysis
        df['user_agent_category'] = df['userAgent'].apply(self._categorize_user_agent)
        df['is_automated'] = df['userAgent'].str.contains('Boto|aws-cli|terraform', case=False, na=False).astype(int)

        return df

    def create_behavioral_features(self, df):
        """Create behavioral features by analyzing user patterns"""
        print("Creating behavioral features...")

        # Sort by user and time
        df = df.sort_values(['userName', 'eventTime'])

        # Create session-based features
        behavioral_features = []

        for user in df['userName'].unique():
            user_data = df[df['userName'] == user].copy()
            user_data = user_data.sort_values('eventTime')

            # Rolling window features (last 10 events)
            window_size = 10

            for i in range(len(user_data)):
                start_idx = max(0, i - window_size + 1)
                window_data = user_data.iloc[start_idx:i+1]

                features = {
                    'event_index': i,
                    'window_size': len(window_data),
                    'error_rate': window_data['isError'].mean(),
                    'unique_regions': window_data['awsRegion'].nunique(),
                    'unique_services': window_data['eventSource'].nunique(),
                    'unique_operations': window_data['eventName'].nunique(),
                    'read_write_ratio': window_data['is_read_operation'].sum() / max(1, window_data['is_write_operation'].sum()),
                    'high_risk_count': window_data['is_high_risk_operation'].sum(),
                    'time_span_minutes': (window_data['eventTime'].max() - window_data['eventTime'].min()).total_seconds() / 60,
                    'events_per_minute': len(window_data) / max(1, (window_data['eventTime'].max() - window_data['eventTime'].min()).total_seconds() / 60)
                }

                behavioral_features.append(features)

        behavioral_df = pd.DataFrame(behavioral_features)

        # Merge back with original data
        df = df.reset_index(drop=True)
        df = pd.concat([df, behavioral_df], axis=1)

        return df

    def label_security_events(self, df):
        """Create labels for supervised learning based on security indicators"""
        print("Creating security labels...")

        # Initialize all as normal
        df['security_label'] = 'Normal'

        # High error rate indicates potential attack
        high_error_threshold = 0.7
        df.loc[df['error_rate'] > high_error_threshold, 'security_label'] = 'Suspicious'

        # Multiple regions in short time (reconnaissance)
        df.loc[(df['unique_regions'] > 3) & (df['time_span_minutes'] < 30), 'security_label'] = 'Reconnaissance'

        # High-risk operations with errors
        df.loc[(df['high_risk_count'] > 0) & (df['isError'] == 1), 'security_label'] = 'Privilege_Escalation'

        # Expensive instance types (resource abuse)
        expensive_instances = df['eventName'].str.contains('RunInstances', na=False) & \
                            (df['errorCode'].str.contains('InstanceLimitExceeded|Unsupported', na=False))
        df.loc[expensive_instances, 'security_label'] = 'Resource_Abuse'

        # High activity rate (potential automation/bot)
        df.loc[df['events_per_minute'] > 10, 'security_label'] = 'Automated_Attack'

        return df

    def prepare_lstm_sequences(self, df, sequence_length=20):
        """Prepare sequential data for LSTM model"""
        print(f"Preparing LSTM sequences with length {sequence_length}...")

        # Select features for LSTM
        feature_columns = [
            'isError', 'is_read_operation', 'is_write_operation', 'is_high_risk_operation',
            'hour', 'day_of_week', 'is_weekend', 'is_business_hours',
            'error_rate', 'unique_regions', 'unique_services', 'events_per_minute',
            'is_internal_ip', 'is_aws_service', 'is_automated'
        ]

        # Encode categorical features
        categorical_columns = ['eventName', 'eventSource', 'awsRegion', 'errorCode', 'userType']

        for col in categorical_columns:
            if col not in self.label_encoders:
                self.label_encoders[col] = LabelEncoder()
                df[f'{col}_encoded'] = self.label_encoders[col].fit_transform(df[col].astype(str))
            else:
                # Handle unseen labels by assigning them to a default value
                col_values = df[col].astype(str)
                known_classes = set(self.label_encoders[col].classes_)
                unknown_mask = ~col_values.isin(known_classes)

                if unknown_mask.any():
                    print(f"Warning: Found {unknown_mask.sum()} unknown {col} values, mapping to 'Unknown'")
                    col_values[unknown_mask] = 'Unknown'

                    # Add 'Unknown' to encoder if not present
                    if 'Unknown' not in known_classes:
                        # Refit encoder with Unknown category
                        all_values = list(self.label_encoders[col].classes_) + ['Unknown']
                        self.label_encoders[col].fit(all_values)

                df[f'{col}_encoded'] = self.label_encoders[col].transform(col_values)
            feature_columns.append(f'{col}_encoded')

        # Encode security labels
        if 'security_label_encoded' not in df.columns:
            self.label_encoders['security_label'] = LabelEncoder()
            df['security_label_encoded'] = self.label_encoders['security_label'].fit_transform(df['security_label'])

        # Normalize numerical features
        numerical_features = ['error_rate', 'unique_regions', 'unique_services', 'events_per_minute']
        df[numerical_features] = self.scaler.fit_transform(df[numerical_features])

        # Create sequences
        sequences = []
        labels = []

        for user in df['userName'].unique():
            user_data = df[df['userName'] == user].sort_values('eventTime')

            if len(user_data) >= sequence_length:
                user_features = user_data[feature_columns].values.astype(np.float32)
                user_labels = user_data['security_label_encoded'].values.astype(np.int32)

                for i in range(len(user_data) - sequence_length + 1):
                    sequences.append(user_features[i:i + sequence_length])
                    labels.append(user_labels[i + sequence_length - 1])  # Predict the last event in sequence

        return np.array(sequences, dtype=np.float32), np.array(labels, dtype=np.int32)

    def _is_internal_ip(self, ip_str):
        """Check if IP address is internal/private"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except:
            return False

    def _categorize_user_agent(self, user_agent):
        """Categorize user agent strings"""
        if pd.isna(user_agent):
            return 'Unknown'

        user_agent = str(user_agent).lower()

        if 'boto' in user_agent:
            return 'Boto_SDK'
        elif 'aws-cli' in user_agent:
            return 'AWS_CLI'
        elif 'terraform' in user_agent:
            return 'Terraform'
        elif 'console' in user_agent:
            return 'AWS_Console'
        else:
            return 'Other'

def main():
    # Initialize processor
    processor = CloudTrailProcessor()

    # Load data
    df = processor.load_cloudtrail_data('flaws_cloudtrail_logs/flaws_cloudtrail01.json')

    # Extract basic features
    features_df = processor.extract_basic_features(df)

    # Engineer advanced features
    features_df = processor.engineer_advanced_features(features_df)

    # Create behavioral features
    features_df = processor.create_behavioral_features(features_df)

    # Label security events
    features_df = processor.label_security_events(features_df)

    # Prepare LSTM sequences
    X, y = processor.prepare_lstm_sequences(features_df)

    print(f"Generated {len(X)} sequences for training")
    print(f"Sequence shape: {X.shape}")
    print(f"Label distribution:")
    unique, counts = np.unique(y, return_counts=True)
    for label, count in zip(unique, counts):
        label_name = processor.label_encoders['security_label'].inverse_transform([label])[0]
        print(f"  {label_name}: {count}")

    # Save processed data
    np.save('lstm_sequences.npy', X, allow_pickle=True)
    np.save('lstm_labels.npy', y, allow_pickle=True)
    features_df.to_csv('processed_features.csv', index=False)

    print("Data preprocessing completed!")
    return X, y, features_df

if __name__ == "__main__":
    X, y, df = main()