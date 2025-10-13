import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout, BatchNormalization
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import joblib

class IAMThreatLSTM:
    def __init__(self, sequence_length=50, num_features=20, num_classes=6):
        self.sequence_length = sequence_length
        self.num_features = num_features
        self.num_classes = num_classes
        self.model = None
        self.history = None

    def build_model(self, lstm_units=128, dropout_rate=0.3):
        """Build LSTM model architecture"""
        print("Building LSTM model...")

        model = Sequential([
            # First LSTM layer with return sequences
            LSTM(lstm_units, return_sequences=True, input_shape=(self.sequence_length, self.num_features)),
            BatchNormalization(),
            Dropout(dropout_rate),

            # Second LSTM layer
            LSTM(lstm_units // 2, return_sequences=False),
            BatchNormalization(),
            Dropout(dropout_rate),

            # Dense layers
            Dense(64, activation='relu'),
            Dropout(dropout_rate),
            Dense(32, activation='relu'),
            Dropout(dropout_rate),

            # Output layer
            Dense(self.num_classes, activation='softmax')
        ])

        # Compile model
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )

        self.model = model
        print(f"Model built with {model.count_params()} parameters")
        return model

    def train(self, X_train, y_train, X_val, y_val, epochs=100, batch_size=32):
        """Train the LSTM model"""
        print("Training LSTM model...")

        # Callbacks
        callbacks = [
            EarlyStopping(
                monitor='val_loss',
                patience=15,
                restore_best_weights=True,
                verbose=1
            ),
            ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=8,
                min_lr=1e-7,
                verbose=1
            )
        ]

        # Train model
        self.history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            verbose=1
        )

        return self.history

    def evaluate(self, X_test, y_test, label_encoder):
        """Evaluate model performance"""
        print("Evaluating model...")

        # Predictions
        y_pred_proba = self.model.predict(X_test)
        y_pred = np.argmax(y_pred_proba, axis=1)

        # Accuracy
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Test Accuracy: {accuracy:.4f}")

        # Classification report with proper class handling
        unique_test_classes = np.unique(y_test)
        unique_pred_classes = np.unique(y_pred)
        all_classes = np.unique(np.concatenate([unique_test_classes, unique_pred_classes]))

        # Get class names for the classes that actually appear
        class_names = []
        for class_idx in all_classes:
            if class_idx < len(label_encoder.classes_):
                class_names.append(label_encoder.classes_[class_idx])
            else:
                class_names.append(f'Unknown_Class_{class_idx}')

        report = classification_report(y_test, y_pred, labels=all_classes, target_names=class_names, output_dict=True)

        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, labels=all_classes, target_names=class_names))

        return {
            'accuracy': accuracy,
            'predictions': y_pred,
            'probabilities': y_pred_proba,
            'classification_report': report
        }

    def predict_threat(self, sequence, label_encoder, threshold=0.8):
        """Predict threat for a single sequence with production tuning"""
        if len(sequence.shape) == 2:
            sequence = sequence.reshape(1, sequence.shape[0], sequence.shape[1])

        prediction_proba = self.model.predict(sequence, verbose=0)
        predicted_class = np.argmax(prediction_proba, axis=1)[0]
        confidence = np.max(prediction_proba)

        # Handle unknown classes safely
        if predicted_class < len(label_encoder.classes_):
            threat_type = label_encoder.inverse_transform([predicted_class])[0]
        else:
            threat_type = 'Unknown_Threat'

        # Production-tuned threat detection
        is_threat = threat_type != 'Normal' and confidence > threshold

        # Additional production logic
        risk_score = self._calculate_risk_score(prediction_proba[0], label_encoder)

        return {
            'threat_type': threat_type,
            'confidence': confidence,
            'risk_score': risk_score,
            'is_threat': is_threat,
            'requires_investigation': confidence > 0.9 and threat_type != 'Normal',
            'all_probabilities': dict(zip(label_encoder.classes_, prediction_proba[0]))
        }

    def _calculate_risk_score(self, probabilities, label_encoder):
        """Calculate weighted risk score for production alerting"""
        # Define risk weights for different threat types
        risk_weights = {
            'Normal': 0.0,
            'Suspicious': 0.3,
            'Reconnaissance': 0.6,
            'Privilege_Escalation': 0.9,
            'Resource_Abuse': 0.7,
            'Automated_Attack': 0.8
        }

        risk_score = 0.0
        for i, class_name in enumerate(label_encoder.classes_):
            weight = risk_weights.get(class_name, 0.5)
            risk_score += probabilities[i] * weight

        return min(risk_score, 1.0)  # Cap at 1.0

    def tune_threshold_for_production(self, X_val, y_val, label_encoder, target_fpr=0.01):
        """Tune threshold to achieve target false positive rate"""
        print(f"Tuning threshold for target FPR: {target_fpr:.1%}")

        # Get predictions for validation set
        predictions = []
        for i in range(len(X_val)):
            result = self.predict_threat(X_val[i:i+1], label_encoder, threshold=0.5)
            predictions.append(result)

        # Calculate metrics at different thresholds
        thresholds = np.arange(0.5, 0.99, 0.02)
        best_threshold = 0.8
        best_metrics = None

        for threshold in thresholds:
            tp = fp = tn = fn = 0

            for i, pred in enumerate(predictions):
                actual_threat = y_val[i] != 0  # 0 = Normal
                predicted_threat = pred['confidence'] > threshold and pred['threat_type'] != 'Normal'

                if actual_threat and predicted_threat:
                    tp += 1
                elif not actual_threat and predicted_threat:
                    fp += 1
                elif not actual_threat and not predicted_threat:
                    tn += 1
                else:
                    fn += 1

            if (fp + tn) > 0:
                fpr = fp / (fp + tn)
                if tp + fn > 0:
                    tpr = tp / (tp + fn)
                    if fpr <= target_fpr:
                        metrics = {
                            'threshold': threshold,
                            'fpr': fpr,
                            'tpr': tpr,
                            'precision': tp / (tp + fp) if (tp + fp) > 0 else 0,
                            'recall': tpr
                        }
                        if best_metrics is None or tpr > best_metrics['tpr']:
                            best_threshold = threshold
                            best_metrics = metrics

        if best_metrics:
            print(f"Optimal threshold: {best_threshold:.3f}")
            print(f"FPR: {best_metrics['fpr']:.3f}, TPR: {best_metrics['tpr']:.3f}")
            print(f"Precision: {best_metrics['precision']:.3f}, Recall: {best_metrics['recall']:.3f}")

        return best_threshold, best_metrics

    def save_model(self, filepath):
        """Save trained model"""
        self.model.save(filepath)
        print(f"Model saved to {filepath}")

    def load_model(self, filepath):
        """Load trained model"""
        self.model = tf.keras.models.load_model(filepath)
        print(f"Model loaded from {filepath}")

class ThreatAnalyzer:
    def __init__(self, model, label_encoder):
        self.model = model
        self.label_encoder = label_encoder

    def analyze_user_behavior(self, user_sequences, user_name):
        """Analyze behavior patterns for a specific user"""
        threat_scores = []
        threat_types = []

        for sequence in user_sequences:
            result = self.model.predict_threat(sequence, self.label_encoder)
            threat_scores.append(result['confidence'])
            threat_types.append(result['threat_type'])

        # Calculate risk metrics
        avg_threat_score = np.mean(threat_scores)
        max_threat_score = np.max(threat_scores)
        threat_frequency = len([t for t in threat_types if t != 'Normal']) / len(threat_types)

        return {
            'user': user_name,
            'average_threat_score': avg_threat_score,
            'max_threat_score': max_threat_score,
            'threat_frequency': threat_frequency,
            'threat_types': threat_types,
            'risk_level': self._classify_risk_level(avg_threat_score, threat_frequency)
        }

    def _classify_risk_level(self, avg_score, frequency):
        """Classify overall risk level"""
        if avg_score > 0.8 or frequency > 0.5:
            return 'HIGH'
        elif avg_score > 0.6 or frequency > 0.3:
            return 'MEDIUM'
        else:
            return 'LOW'

def plot_training_history(history):
    """Plot training history"""
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # Loss
    axes[0].plot(history.history['loss'], label='Training Loss')
    axes[0].plot(history.history['val_loss'], label='Validation Loss')
    axes[0].set_title('Model Loss')
    axes[0].set_xlabel('Epoch')
    axes[0].set_ylabel('Loss')
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)

    # Accuracy
    axes[1].plot(history.history['accuracy'], label='Training Accuracy')
    axes[1].plot(history.history['val_accuracy'], label='Validation Accuracy')
    axes[1].set_title('Model Accuracy')
    axes[1].set_xlabel('Epoch')
    axes[1].set_ylabel('Accuracy')
    axes[1].legend()
    axes[1].grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig('training_history.png', dpi=300, bbox_inches='tight')
    plt.show()

def plot_confusion_matrix(y_true, y_pred, class_names):
    """Plot confusion matrix"""
    cm = confusion_matrix(y_true, y_pred)

    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=class_names, yticklabels=class_names)
    plt.title('Confusion Matrix')
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.savefig('confusion_matrix.png', dpi=300, bbox_inches='tight')
    plt.show()

def plot_threat_distribution(y_true, class_names):
    """Plot threat type distribution"""
    unique, counts = np.unique(y_true, return_counts=True)
    threat_names = [class_names[i] for i in unique]

    plt.figure(figsize=(12, 6))
    bars = plt.bar(threat_names, counts)
    plt.title('Distribution of Threat Types')
    plt.xlabel('Threat Type')
    plt.ylabel('Count')
    plt.xticks(rotation=45)

    # Add count labels on bars
    for bar, count in zip(bars, counts):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + count*0.01,
                str(count), ha='center', va='bottom')

    plt.tight_layout()
    plt.savefig('threat_distribution.png', dpi=300, bbox_inches='tight')
    plt.show()

def main():
    print("Starting LSTM IAM Threat Detection Model Training...")

    # Load preprocessed data
    try:
        X = np.load('lstm_sequences.npy', allow_pickle=True)
        y = np.load('lstm_labels.npy', allow_pickle=True)
        print(f"Loaded data: X shape {X.shape}, y shape {y.shape}")
    except FileNotFoundError:
        print("Preprocessed data not found. Please run cloudtrail_processor.py first.")
        return

    # Load label encoder
    df = pd.read_csv('processed_features.csv')
    from cloudtrail_processor import CloudTrailProcessor
    processor = CloudTrailProcessor()
    processor.label_encoders['security_label'] = joblib.load('security_label_encoder.pkl') if os.path.exists('security_label_encoder.pkl') else None

    if processor.label_encoders['security_label'] is None:
        # Create label encoder from data
        from sklearn.preprocessing import LabelEncoder
        le = LabelEncoder()
        le.fit(df['security_label'].unique())
        processor.label_encoders['security_label'] = le
        joblib.dump(le, 'security_label_encoder.pkl')

    # Split data
    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp)

    print(f"Training set: {X_train.shape}")
    print(f"Validation set: {X_val.shape}")
    print(f"Test set: {X_test.shape}")

    # Initialize and build model
    num_features = X.shape[2]
    num_classes = len(np.unique(y))

    lstm_model = IAMThreatLSTM(
        sequence_length=X.shape[1],
        num_features=num_features,
        num_classes=num_classes
    )

    lstm_model.build_model()
    print(lstm_model.model.summary())

    # Train model
    history = lstm_model.train(X_train, y_train, X_val, y_val, epochs=50, batch_size=64)

    # Evaluate model
    results = lstm_model.evaluate(X_test, y_test, processor.label_encoders['security_label'])

    # Plot results
    plot_training_history(history)
    plot_confusion_matrix(y_test, results['predictions'], processor.label_encoders['security_label'].classes_)
    plot_threat_distribution(y, processor.label_encoders['security_label'].classes_)

    # Save model
    lstm_model.save_model('iam_threat_lstm_model.h5')

    # Create threat analyzer
    analyzer = ThreatAnalyzer(lstm_model, processor.label_encoders['security_label'])

    # Example threat analysis
    print("\n=== THREAT ANALYSIS EXAMPLE ===")
    # Analyze a few random sequences
    for i in range(3):
        sample_sequence = X_test[i:i+1]
        threat_result = lstm_model.predict_threat(sample_sequence, processor.label_encoders['security_label'])

        print(f"\nSequence {i+1}:")
        print(f"  Predicted Threat: {threat_result['threat_type']}")
        print(f"  Confidence: {threat_result['confidence']:.3f}")
        print(f"  Is Threat: {threat_result['is_threat']}")
        print(f"  Actual Label: {processor.label_encoders['security_label'].inverse_transform([y_test[i]])[0]}")

    print("\nModel training and evaluation completed!")
    return lstm_model, analyzer, results

if __name__ == "__main__":
    import os
    model, analyzer, results = main()