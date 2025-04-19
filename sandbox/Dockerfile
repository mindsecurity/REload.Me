# sandbox/Dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install required tools
RUN apt-get update && apt-get install -y \
    strace \
    ltrace \
    gdb \
    tcpdump \
    python3 \
    python3-pip \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for sandboxed execution
RUN useradd -m -s /bin/bash sandboxuser

# Create working directory
WORKDIR /app

# Copy monitoring script
COPY trace.sh /app/trace.sh
RUN chmod +x /app/trace.sh

# Set up security restrictions
RUN chown -R sandboxuser:sandboxuser /app

# Switch to non-root user
USER sandboxuser

# Entry point will be the trace script
ENTRYPOINT ["/app/trace.sh"]