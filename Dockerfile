# NodeCast TV Docker Image
#
# Hardware acceleration:
#   - VAAPI (Intel/AMD): Mount /dev/dri and add video/render groups
#   - NVIDIA NVENC: Requires nvidia-container-toolkit on host + --gpus flag
#   - Intel QSV: Mount /dev/dri
#
# Build: docker compose build
# Run with VAAPI: docker run --device /dev/dri:/dev/dri --group-add video ...

FROM ubuntu:24.04

# Install Node.js, FFmpeg, and hardware acceleration drivers
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive

# Security: pull latest patches for the base image before installing anything else.
# This addresses CVEs in packages inherited from the ubuntu:24.04 base layer
# (e.g. linux-libc-dev, libssl3t64, openssl) that are present in the base image
# at build time but already have fixes published in Ubuntu's stable repos.
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && if [ "$TARGETARCH" = "amd64" ]; then \
        DRIVERS="mesa-va-drivers intel-media-va-driver vainfo"; \
    else \
        DRIVERS=""; \
    fi \
    && apt-get update && apt-get install -y --no-install-recommends \
    nodejs \
    ffmpeg \
    python3 \
    make \
    g++ \
    $DRIVERS \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Verify FFmpeg installed
RUN ffmpeg -version && ffmpeg -encoders 2>/dev/null | grep -E "vaapi|nvenc|qsv|libx264" | head -10

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (better-sqlite3 will build from source using g++ installed above)
# npm audit fix is run here against package-lock.json to pull in patched versions
# of transitive dependencies (tar, minimatch, glob, cross-spawn, path-to-regexp, etc.)
RUN npm ci --only=production && npm audit fix --only=production || true

# Copy application files
COPY . .

# Create data and cache directories
RUN mkdir -p /app/data /app/transcode-cache && chmod 777 /app/transcode-cache

# Expose port
EXPOSE 3000

# Start server
CMD ["node", "server/index.js"]