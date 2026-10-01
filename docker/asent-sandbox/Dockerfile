# ASENT Sandbox: Hardened execution environment for untrusted candidate packages
FROM python:3.12-slim

# Install minimal observation tooling (strace)
RUN apt-get update && \
    apt-get install -y --no-install-recommends strace && \
    rm -rf /var/lib/apt/lists/*

# Create unprivileged sandbox user
RUN useradd -u 10001 -m -s /bin/false sandbox

# Setup harness directory
RUN mkdir -p /opt/asent && \
    chown -R root:root /opt/asent && \
    chmod 755 /opt/asent

# Copy harness
COPY harness.py /opt/asent/harness.py
RUN chmod 644 /opt/asent/harness.py

# Disposable mount points
RUN mkdir -p /pkg /scratch && \
    chown sandbox:sandbox /scratch && \
    chmod 700 /scratch

USER 10001:10001
WORKDIR /scratch

ENTRYPOINT ["python", "/opt/asent/harness.py"]
CMD ["/pkg"]
