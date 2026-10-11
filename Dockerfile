# syntax=docker/dockerfile:1
# Multi-stage reproducible container for QSC (Quantum-Safe Channel)
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    ninja-build \
    git \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    libssl-dev \
    ca-certificates \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .

RUN python3 -m pip install --break-system-packages --no-cache-dir -r requirements.txt

# Pre-build / pre-cache liboqs C library via python wrapper
RUN python3 -c "import oqs; print('liboqs built successfully')"

FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    iproute2 \
    net-tools \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy installed python site-packages and liboqs shared libraries from builder
COPY --from=builder /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=builder /root/_oqs /root/_oqs

ENV LD_LIBRARY_PATH="/root/_oqs/lib:${LD_LIBRARY_PATH}"
ENV OQS_INSTALL_PATH="/root/_oqs"
ENV PYTHONPATH="/app"

WORKDIR /app
COPY . .

# Install editable CLI entry point
RUN python3 -m pip install --break-system-packages -e .

EXPOSE 8443
ENTRYPOINT ["qsc"]
CMD ["--help"]
