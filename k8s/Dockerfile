FROM python:3.12-slim
RUN pip install flask
RUN apt-get update && apt-get install -y cmake ninja-build libssl-dev git && \
    git clone --recursive https://github.com/open-quantum-safe/liboqs-python && \
    cd liboqs-python && pip install .
COPY aegis_k8s_receiver.py /app/app.py
WORKDIR /app
CMD ["python3", "app.py"]
