import os
import json
import time
from uuid import uuid4
from typing import List, Any

import boto3
import botocore
import numpy as np
from tensorflow.keras.models import load_model

# =========================
# Environment configuration
# =========================
MODEL_BUCKET = os.environ["MODEL_BUCKET"]          # e.g. my-lambda-model-bucket-123
MODEL_KEY    = os.environ["MODEL_KEY"]             # e.g. models/iam_threat_production_model.h5
DDB_TABLE    = os.environ["DDB_TABLE"]             # e.g. iam-threat-scores
THRESHOLD    = float(os.environ.get("THRESHOLD", "1.01"))  # optional alert threshold
ALERT_TOPIC  = os.environ.get("ALERT_TOPIC_ARN")   # optional SNS topic ARN (or leave unset)

LOCAL_MODEL  = "/tmp/" + os.path.basename(MODEL_KEY)

# Input shape your saved model expects
MODEL_ROWS, MODEL_COLS = 20, 20

# ==============
# AWS clients
# ==============
s3  = boto3.client("s3", config=botocore.config.Config(retries={"max_attempts": 3}))
ddb = boto3.client("dynamodb")
sns = boto3.client("sns")

# Cache the model across invocations
_model = None


# ======================
# Helper: fetch the model
# ======================
def _ensure_model_local() -> str:
    """Download the model to /tmp if missing (cold start)."""
    if not os.path.exists(LOCAL_MODEL):
        print(f"Downloading s3://{MODEL_BUCKET}/{MODEL_KEY} -> {LOCAL_MODEL}")
        s3.download_file(MODEL_BUCKET, MODEL_KEY, LOCAL_MODEL)
    return LOCAL_MODEL


def _load_model():
    """Load and cache the Keras model."""
    global _model
    if _model is None:
        t0 = time.time()
        path = _ensure_model_local()
        _model = load_model(path)
        print(f"Model loaded in {time.time() - t0:.2f}s")
    return _model


# ====================================
# Feature extraction for EventBridge path
# (stub — replace with your real logic)
# ====================================
def extract_features_from_cloudtrail(detail: dict) -> List[float]:
    """
    Map CloudTrail 'detail' into your model features.
    This stub yields ~5 simple signals so the pipeline runs.
    """
    ts = detail.get("eventTime", "")
    hour = int(ts[11:13]) if len(ts) >= 13 else 0

    ua = (detail.get("userAgent") or "").lower()
    is_console = 1.0 if ua.startswith("signin") or "console" in ua else 0.0

    event_name = detail.get("eventName", "")
    action_bucket = float(hash(event_name) % 10) / 10.0

    user_type = 1.0 if detail.get("userIdentity", {}).get("type") == "IAMUser" else 0.0

    vec = [hour/23.0, is_console, action_bucket, user_type, 0.0]
    return vec[:5]


# ============================
# Input coercion to (20 x 20)
# ============================
def _pad_row(row: List[float]) -> List[float]:
    """Pad/trim a row to exactly MODEL_COLS elements."""
    row = (row or [])[:MODEL_COLS]
    if len(row) < MODEL_COLS:
        row = row + [0.0] * (MODEL_COLS - len(row))
    return [float(v) for v in row]


def _to_model_2d_from_1d(vec: List[float]) -> List[List[float]]:
    """Put a 1D feature vector into the first row of a 20x20 zero matrix."""
    mat = [[0.0] * MODEL_COLS for _ in range(MODEL_ROWS)]
    for j, v in enumerate(vec[:MODEL_COLS]):
        mat[0][j] = float(v)
    return mat


def _fix_2d(mat: List[List[float]]) -> List[List[float]]:
    """Coerce a 2D list into exactly 20x20 via pad/trim."""
    mat = mat[:MODEL_ROWS]
    mat = [_pad_row(r) for r in mat]
    if len(mat) < MODEL_ROWS:
        mat += [[0.0] * MODEL_COLS for _ in range(MODEL_ROWS - len(mat))]
    return mat


def coerce_inputs(obj: Any) -> np.ndarray:
    """
    Accept:
      - a single 1D vector: [f1, f2, ...]
      - a single 2D matrix: [[...], [...], ...]
      - a batch (list) of 1D or 2D items
    Return: np.ndarray with shape (batch, 20, 20)
    """
    def one(item: Any) -> List[List[float]]:
        if isinstance(item, list) and (not item or not isinstance(item[0], list)):
            # 1D -> 20x20
            return _to_model_2d_from_1d(item)
        if isinstance(item, list) and item and isinstance(item[0], list):
            # 2D -> coerce
            return _fix_2d(item)
        raise ValueError("Unsupported inputs element; must be 1D vector or 2D list")

    # Batch of 1D (e.g. [[...], [...]])
    if isinstance(obj, list) and obj and isinstance(obj[0], list) and (not obj[0] or not isinstance(obj[0][0], list)):
        batch = [one(v) for v in obj]
    # Batch of 2D (e.g. [[[...],[...]], [[...],[...]]])
    elif isinstance(obj, list) and obj and isinstance(obj[0], list) and isinstance(obj[0][0], list):
        batch = [one(m) for m in obj]
    # Single item (1D or 2D)
    else:
        batch = [one(obj)]

    arr = np.array(batch, dtype=np.float32)
    # Final sanity
    if arr.shape[1:] != (MODEL_ROWS, MODEL_COLS):
        raise ValueError(f"Coerced inputs have shape {arr.shape}; expected (*, {MODEL_ROWS}, {MODEL_COLS})")
    return arr


# =====================
# Main Lambda handler
# =====================
def handler(event, context):
    """
    Supports two invocation styles:

    1) EventBridge / CloudTrail:
       event = {..., "detail": { <cloudtrail> } }

    2) Direct (API Gateway / CLI test):
       event = {"inputs": [ ... ]}  # 1D vector, 20x20 matrix, or batch of either
    """
    # Determine source & build inputs
    metadata = {"source": None}
    if "detail" in event:
        metadata["source"] = "eventbridge"
        metadata["eventId"] = event.get("id")
        features = extract_features_from_cloudtrail(event["detail"])
        x = coerce_inputs(features)  # -> (1, 20, 20)
    else:
        metadata["source"] = "api"
        body = event if isinstance(event, dict) else json.loads(event.get("body", "{}") or "{}")
        x = coerce_inputs(body.get("inputs", [0.0, 0.0, 0.0, 0.0, 0.0]))

    # Inference
    model = _load_model()
    probs = model.predict(x)[0].tolist()  # first item in batch
    risk = float(max(probs))              # adjust if a specific class means "threat"

    # Persist to DynamoDB
    item = {
        "pk":   {"S": metadata.get("eventId") or str(uuid4())},
        "ts":   {"N": str(int(time.time()))},
        "risk": {"N": str(risk)},
        "probs": {"S": json.dumps(probs)},
        "meta": {"S": json.dumps(metadata)},
    }
    ddb.put_item(TableName=DDB_TABLE, Item=item)

    # Optional alerting
    if ALERT_TOPIC and risk >= THRESHOLD:
        sns.publish(
            TopicArn=ALERT_TOPIC,
            Subject="High IAM risk detected",
            Message=json.dumps({"risk": risk, "probs": probs, **metadata})
        )

    # Response
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"risk": risk, "predictions": probs})
    }
