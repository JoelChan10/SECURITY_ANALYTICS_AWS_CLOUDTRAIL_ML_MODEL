FROM public.ecr.aws/lambda/python:3.10

ENV KERAS_BACKEND=tensorflow

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir --only-binary=:all: -r requirements.txt \
 && python - <<'PY'
import keras, os
print("Keras:", keras.__version__, "Backend:", os.getenv("KERAS_BACKEND"))
PY

COPY lambda_function.py .
CMD ["lambda_function.handler"]
