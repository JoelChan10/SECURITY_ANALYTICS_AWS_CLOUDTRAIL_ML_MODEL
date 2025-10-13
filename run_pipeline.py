#!/usr/bin/env python3
"""
Complete IAM Threat Detection Pipeline
Runs preprocessing, model training, and results visualization
"""

import os
import sys
import warnings
import joblib
from datetime import datetime

warnings.filterwarnings('ignore')

def check_dependencies():
    """Check if required packages are installed"""
    required_packages = [
        ('pandas', 'pandas'),
        ('numpy', 'numpy'),
        ('sklearn', 'scikit-learn'),
        ('tensorflow', 'tensorflow'),
        ('matplotlib', 'matplotlib'),
        ('seaborn', 'seaborn'),
        ('plotly', 'plotly')
    ]

    missing_packages = []

    for import_name, package_name in required_packages:
        try:
            __import__(import_name)
        except ImportError:
            missing_packages.append(package_name)

    if missing_packages:
        print("Missing required packages:")
        for package in missing_packages:
            print(f"   - {package}")
        print("\nInstall with: pip install " + " ".join(missing_packages))
        return False

    return True

def run_preprocessing():
    """Run data preprocessing pipeline"""
    print("\n" + "="*60)
    print("STEP 1: DATA PREPROCESSING")
    print("="*60)

    try:
        from cloudtrail_processor import CloudTrailProcessor
        import pandas as pd
        import numpy as np

        processor = CloudTrailProcessor()

        # Load and process data
        df = processor.load_cloudtrail_data('flaws_cloudtrail_logs/flaws_cloudtrail01.json')
        features_df = processor.extract_basic_features(df)
        features_df = processor.engineer_advanced_features(features_df)
        features_df = processor.create_behavioral_features(features_df)
        features_df = processor.label_security_events(features_df)

        # Prepare LSTM sequences
        X, y = processor.prepare_lstm_sequences(features_df)

        # Save processed data
        np.save('lstm_sequences.npy', X)
        np.save('lstm_labels.npy', y)
        features_df.to_csv('processed_features.csv', index=False)

        # Save label encoder
        joblib.dump(processor.label_encoders['security_label'], 'security_label_encoder.pkl')

        print(f"Preprocessing completed!")
        print(f"   - Generated {len(X)} sequences")
        print(f"   - Sequence shape: {X.shape}")
        print(f"   - Saved to lstm_sequences.npy and lstm_labels.npy")

        return True

    except Exception as e:
        print(f"Preprocessing failed: {str(e)}")
        return False

def run_model_training():
    """Run LSTM model training"""
    print("\n" + "="*60)
    print("STEP 2: MODEL TRAINING")
    print("="*60)

    try:
        from lstm_model import IAMThreatLSTM, ThreatAnalyzer, plot_training_history, plot_confusion_matrix, plot_threat_distribution
        from sklearn.model_selection import train_test_split
        import numpy as np
        import joblib

        # Load data
        X = np.load('lstm_sequences.npy', allow_pickle=True)
        y = np.load('lstm_labels.npy', allow_pickle=True)
        label_encoder = joblib.load('security_label_encoder.pkl')

        print(f"Loaded data: X shape {X.shape}, y shape {y.shape}")

        # Split data
        X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
        X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp)

        # Build and train model
        lstm_model = IAMThreatLSTM(
            sequence_length=X.shape[1],
            num_features=X.shape[2],
            num_classes=len(np.unique(y))
        )

        lstm_model.build_model()
        print(f"Model built with {lstm_model.model.count_params():,} parameters")

        # Train model
        history = lstm_model.train(X_train, y_train, X_val, y_val, epochs=3, batch_size=128)

        # Evaluate model
        results = lstm_model.evaluate(X_test, y_test, label_encoder)

        # Generate plots
        plot_training_history(history)
        plot_confusion_matrix(y_test, results['predictions'], label_encoder.classes_)
        plot_threat_distribution(y, label_encoder.classes_)

        # Save model and results
        lstm_model.save_model('iam_threat_lstm_model.h5')
        joblib.dump(results, 'model_results.pkl')

        print(f"Model training completed!")
        print(f"   - Final accuracy: {results['accuracy']:.3f}")
        print(f"   - Model saved to iam_threat_lstm_model.h5")

        return True, lstm_model, results

    except Exception as e:
        print(f"Model training failed: {str(e)}")
        return False, None, None

def run_results_analysis():
    """Run results analysis and visualization"""
    print("\n" + "="*60)
    print("STEP 3: RESULTS ANALYSIS")
    print("="*60)

    try:
        import subprocess
        import sys

        # Run the comprehensive results generator
        result = subprocess.run([sys.executable, 'generate_final_results.py'],
                              capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            print("Results analysis completed!")
            print("   - Dashboard saved to iam_threat_detection_final_dashboard.png")
            print("   - Analysis output:")
            print(result.stdout)
            return True
        else:
            print(f"Results analysis failed: {result.stderr}")
            return False

    except Exception as e:
        print(f"Results analysis failed: {str(e)}")
        return False

def main():
    """Main pipeline execution"""
    start_time = datetime.now()

    print("IAM THREAT DETECTION PIPELINE")
    print("=" * 60)
    print(f"Started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Check dependencies
    if not check_dependencies():
        return

    # Check if data file exists
    data_file = 'flaws_cloudtrail_logs/flaws_cloudtrail01.json'
    if not os.path.exists(data_file):
        print(f"Data file not found: {data_file}")
        print("Please ensure the CloudTrail data is available.")
        return

    # Run pipeline steps
    success_count = 0

    # Step 1: Preprocessing
    if run_preprocessing():
        success_count += 1

        # Step 2: Model Training
        training_success, model, results = run_model_training()
        if training_success:
            success_count += 1

            # Step 3: Results Analysis
            if run_results_analysis():
                success_count += 1

    # Final summary
    end_time = datetime.now()
    duration = end_time - start_time

    print("\n" + "="*60)
    print("PIPELINE EXECUTION SUMMARY")
    print("="*60)
    print(f"Completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total duration: {duration}")
    print(f"Steps completed: {success_count}/3")

    if success_count == 3:
        print("Pipeline completed successfully!")
        print("\nGenerated Files:")
        files_created = [
            'lstm_sequences.npy',
            'lstm_labels.npy',
            'processed_features.csv',
            'security_label_encoder.pkl',
            'iam_threat_lstm_model.h5',
            'model_results.pkl',
            'training_history.png',
            'confusion_matrix.png',
            'threat_distribution.png',
            'iam_threat_detection_final_dashboard.png',
            'iam_threat_detection_executive_summary.txt'
        ]

        for file in files_created:
            if os.path.exists(file):
                print(f"   [OK] {file}")
            else:
                print(f"   [MISSING] {file}")

        print("\nNext Steps:")
        print("   1. Review the executive summary")
        print("   2. Examine the threat analysis dashboard")
        print("   3. Fine-tune model parameters if needed")
        print("   4. Deploy for real-time threat detection")

    else:
        print("Pipeline completed with errors. Check the logs above.")

if __name__ == "__main__":
    main()