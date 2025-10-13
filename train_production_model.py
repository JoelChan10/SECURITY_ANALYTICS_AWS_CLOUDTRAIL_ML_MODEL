#!/usr/bin/env python3
"""
Production Model Training with Temporal Validation
Train on multiple time periods and tune for production deployment
"""

import pandas as pd
import numpy as np
from cloudtrail_processor import CloudTrailProcessor
from lstm_model import IAMThreatLSTM
import joblib
from datetime import datetime
import os

def load_multiple_cloudtrail_files():
    """Load and combine multiple CloudTrail files"""
    files = [
        'flaws_cloudtrail_logs/flaws_cloudtrail01.json',  # 2018
        'flaws_cloudtrail_logs/flaws_cloudtrail05.json',  # 2019
        'flaws_cloudtrail_logs/flaws_cloudtrail10.json',  # 2019
        'flaws_cloudtrail_logs/flaws_cloudtrail14.json',  # 2020
        'flaws_cloudtrail_logs/flaws_cloudtrail19.json'   # 2020
    ]

    processor = CloudTrailProcessor()
    all_dataframes = []

    print("Loading CloudTrail files for temporal training...")
    for i, file in enumerate(files):
        if os.path.exists(file):
            print(f"Loading {file}...")
            df = processor.load_cloudtrail_data(file)
            features_df = processor.extract_basic_features(df)
            features_df = processor.engineer_advanced_features(features_df)

            # Add file identifier for temporal analysis
            features_df['source_file'] = f'file_{i+1:02d}'
            features_df['file_year'] = features_df['eventTime'].dt.year

            all_dataframes.append(features_df)
            print(f"  Processed {len(features_df):,} events")
        else:
            print(f"  Skipping {file} (not found)")

    if not all_dataframes:
        raise FileNotFoundError("No CloudTrail files found!")

    # Combine all dataframes
    combined_df = pd.concat(all_dataframes, ignore_index=True)
    print(f"\nCombined dataset: {len(combined_df):,} events")
    print(f"Time range: {combined_df['eventTime'].min()} to {combined_df['eventTime'].max()}")

    return combined_df, processor

def create_temporal_splits(df):
    """Create temporal train/validation/test splits"""
    # Sort by time
    df = df.sort_values('eventTime')

    # Split by year for temporal validation
    df_2018 = df[df['file_year'] == 2018]
    df_2019 = df[df['file_year'] == 2019]
    df_2020 = df[df['file_year'] == 2020]

    print(f"\nTemporal distribution:")
    print(f"2018: {len(df_2018):,} events")
    print(f"2019: {len(df_2019):,} events")
    print(f"2020: {len(df_2020):,} events")

    # Training strategy: Train on 2018, validate on 2019, test on 2020
    train_df = df_2018
    val_df = df_2019.sample(min(len(df_2019), 50000), random_state=42)  # Limit validation size
    test_df = df_2020.sample(min(len(df_2020), 30000), random_state=42)  # Limit test size

    print(f"\nFinal splits:")
    print(f"Train: {len(train_df):,} (2018 data)")
    print(f"Validation: {len(val_df):,} (2019 data)")
    print(f"Test: {len(test_df):,} (2020 data)")

    return train_df, val_df, test_df

def train_production_model():
    """Train model with production features"""
    print("PRODUCTION MODEL TRAINING")
    print("=" * 50)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Load multiple files
    combined_df, processor = load_multiple_cloudtrail_files()

    # Create behavioral features
    print("Creating behavioral features...")
    combined_df = processor.create_behavioral_features(combined_df)

    # Label security events
    print("Labeling security events...")
    combined_df = processor.label_security_events(combined_df)

    # Create temporal splits
    train_df, val_df, test_df = create_temporal_splits(combined_df)

    # Prepare LSTM sequences for each split
    print("\nPreparing LSTM sequences...")

    # Important: Fit encoders on ALL data to handle unseen labels
    print("Fitting encoders on complete dataset...")
    all_data = pd.concat([train_df, val_df, test_df])
    _ = processor.prepare_lstm_sequences(all_data.sample(1000), sequence_length=20)  # Fit encoders

    print("Processing training data...")
    X_train, y_train = processor.prepare_lstm_sequences(train_df, sequence_length=20)

    print("Processing validation data...")
    X_val, y_val = processor.prepare_lstm_sequences(val_df, sequence_length=20)

    print("Processing test data...")
    X_test, y_test = processor.prepare_lstm_sequences(test_df, sequence_length=20)

    print(f"\nSequence shapes:")
    print(f"Train: {X_train.shape}")
    print(f"Validation: {X_val.shape}")
    print(f"Test: {X_test.shape}")

    # Build and train model
    print("\nBuilding production LSTM model...")
    num_features = X_train.shape[2]
    num_classes = len(np.unique(y_train))

    model = IAMThreatLSTM(
        sequence_length=X_train.shape[1],
        num_features=num_features,
        num_classes=num_classes
    )

    model.build_model(lstm_units=64, dropout_rate=0.4)  # Smaller model for production
    print(f"Model built with {model.model.count_params():,} parameters")

    # Train with early stopping
    print("\nTraining model...")
    history = model.train(X_train, y_train, X_val, y_val, epochs=15, batch_size=128)

    # Evaluate on test set (temporal validation)
    print("\nEvaluating on 2020 test data...")
    results = model.evaluate(X_test, y_test, processor.label_encoders['security_label'])

    # Tune threshold for production
    print("\nTuning production threshold...")
    optimal_threshold, metrics = model.tune_threshold_for_production(
        X_val, y_val, processor.label_encoders['security_label'], target_fpr=0.01
    )

    # Save everything
    print("\nSaving production model...")
    model.save_model('iam_threat_production_model.h5')
    joblib.dump(processor.label_encoders['security_label'], 'production_label_encoder.pkl')
    joblib.dump(optimal_threshold, 'production_threshold.pkl')
    joblib.dump(results, 'production_model_results.pkl')

    # Save production metadata
    metadata = {
        'training_date': datetime.now().isoformat(),
        'training_events': len(train_df),
        'validation_events': len(val_df),
        'test_events': len(test_df),
        'temporal_range': f"2018-2020",
        'test_accuracy': results['accuracy'],
        'optimal_threshold': optimal_threshold,
        'target_fpr': 0.01,
        'model_parameters': model.model.count_params()
    }

    joblib.dump(metadata, 'production_metadata.pkl')

    print(f"\nPRODUCTION MODEL TRAINING COMPLETED!")
    print(f"Final accuracy: {results['accuracy']:.3f}")
    print(f"Optimal threshold: {optimal_threshold:.3f}")
    print(f"Training time: ~{(datetime.now().hour):02d}:{(datetime.now().minute):02d}")

    return model, results, optimal_threshold

def quick_production_test():
    """Quick test of production model"""
    print("\nTesting production model...")

    # Load production assets
    model = IAMThreatLSTM(sequence_length=20, num_features=20, num_classes=5)
    model.load_model('iam_threat_production_model.h5')
    label_encoder = joblib.load('production_label_encoder.pkl')
    threshold = joblib.load('production_threshold.pkl')

    # Load test data
    X_test = np.load('lstm_sequences.npy', allow_pickle=True)[:100]  # Small sample

    print("Sample predictions:")
    for i in range(3):
        result = model.predict_threat(X_test[i:i+1], label_encoder, threshold)
        print(f"Sequence {i+1}:")
        print(f"  Threat: {result['threat_type']}")
        print(f"  Confidence: {result['confidence']:.3f}")
        print(f"  Risk Score: {result['risk_score']:.3f}")
        print(f"  Alert: {result['requires_investigation']}")
        print()

if __name__ == "__main__":
    try:
        model, results, threshold = train_production_model()
        quick_production_test()
        print("Production model ready for AWS deployment!")
    except Exception as e:
        print(f"Training failed: {str(e)}")
        import traceback
        traceback.print_exc()