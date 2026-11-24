# OMG application container: HTTP on container port 80.
# Local: publish 80:80. Production: host Nginx owns public 80/443,
# and proxies to a loopback-only published container port (e.g. 8080).
# SSL keys remain on the client-managed host Nginx.
# Tesseract is installed INSIDE this Debian Bookworm image, not via AL2023 dnf.
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    OMG_ENV=production \
    OMG_ENVIRONMENT=production \
    OMG_CLAMAV_HOST=127.0.0.1 \
    OMG_CLAMAV_PORT=3310 \
    OMG_CLAMAV_TIMEOUT=30 \
    OMG_REQUIRE_CLAMAV=true \
    OMG_REQUIRE_ML=true \
    OMG_ENABLE_ML=true \
    OMG_MODEL_PATH=/app/Content/models/email_classifier.joblib \
    OMG_RULES_PATH=/app/Content/data/omg_rules.json

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl nginx clamav clamav-daemon clamav-freshclam \
      supervisor tesseract-ocr tesseract-ocr-eng poppler-utils libmagic1 \
      default-mysql-client \
      file tini \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/clamav /var/log/clamav /run/clamav /var/log/supervisor \
    && chown -R clamav:clamav /var/lib/clamav /var/log/clamav /run/clamav

COPY requirements.txt /app/requirements.txt

RUN python -m pip install --upgrade pip \
    && python -m pip install -r /app/requirements.txt \
    && python -m pip install \
       'pwdlib[argon2,bcrypt]' \
       pytesseract \
       pdf2image \
       Pillow \
       mysql-connector-python

COPY . /app

# Fail early if required OMG code and model/rule assets are missing.
RUN test -f /app/app.py \
    && test -f /app/requirements.txt \
    && test -f /app/frontend/index.html \
    && test -f /app/Content/models/email_classifier.joblib \
    && test -f /app/Content/data/omg_rules.json

# ClamAV is bound to container loopback only; do not publish port 3310.
RUN printf '%s\n' \
    'Foreground yes' \
    'User clamav' \
    'DatabaseDirectory /var/lib/clamav' \
    'LogTime yes' \
    'TCPSocket 3310' \
    'TCPAddr 127.0.0.1' \
    'LocalSocket /run/clamav/clamd.ctl' \
    'FixStaleSocket yes' \
    'StreamMaxLength 100M' \
    'MaxFileSize 100M' \
    'MaxScanSize 150M' \
    'MaxThreads 4' \
    > /etc/clamav/clamd.conf \
    && printf '%s\n' \
    'DatabaseOwner clamav' \
    'DatabaseDirectory /var/lib/clamav' \
    'LogTime yes' \
    'DatabaseMirror database.clamav.net' \
    > /etc/clamav/freshclam.conf
# Preserve HTTPS scheme supplied by trusted host Nginx when applicable.
# Host proxy must overwrite X-Forwarded-Proto, not pass client-supplied values.
RUN printf '%s\n' 'map $http_x_forwarded_proto $omg_forwarded_proto {' '    default $scheme;' '    http http;' '    https https;' '}' > /etc/nginx/conf.d/omg-proto-map.conf

# Nginx is the only published service; it proxies to FastAPI on loopback.
RUN rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf \
    && printf '%s\n' \
    'server {' \
    '    listen 80 default_server;' \
    '    server_name _;' \
    '    client_max_body_size 25M;' \
    '    location / {' \
    '        proxy_pass http://127.0.0.1:8000;' \
    '        proxy_http_version 1.1;' \
    '        proxy_set_header Host $host;' \
    '        proxy_set_header X-Forwarded-Host $host;' \
    '        proxy_set_header X-Real-IP $remote_addr;' \
    '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;' \
    '        proxy_set_header X-Forwarded-Proto $omg_forwarded_proto;' \
    '        proxy_connect_timeout 30s;' \
    '        proxy_read_timeout 300s;' \
    '    }' \
    '}' > /etc/nginx/conf.d/omg.conf

# Store startup scripts and Supervisor configuration without external files.
RUN printf '%s' 'IyEvYmluL3NoCnNldCAtZXUKZWNobyAnW09NR10gVXBkYXRpbmcgQ2xhbUFWIHNpZ25hdHVyZXMgYmVmb3JlIHN0YXJ0dXAuLi4nCmZyZXNoY2xhbSAtLXN0ZG91dCAtLXZlcmJvc2UKZWNobyAnW09NR10gU3RhcnRpbmcgc3VwZXJ2aXNlZCBzZXJ2aWNlcy4uLicKZXhlYyAvdXNyL2Jpbi9zdXBlcnZpc29yZCAtbiAtYyAvZXRjL3N1cGVydmlzb3IvY29uZi5kL29tZy5jb25mCg==' | base64 -d > /usr/local/bin/omg-entrypoint \
    && printf '%s' 'IyEvYmluL3NoCnNldCAtZXUKcHl0aG9uIC0gPDwnUFlXQUlUJwppbXBvcnQgc29ja2V0LCBzeXMsIHRpbWUKZm9yIGF0dGVtcHQgaW4gcmFuZ2UoOTApOgogICAgdHJ5OgogICAgICAgIHdpdGggc29ja2V0LmNyZWF0ZV9jb25uZWN0aW9uKCgnMTI3LjAuMC4xJywgMzMxMCksIHRpbWVvdXQ9MikgYXMgc29jazoKICAgICAgICAgICAgc29jay5zZW5kYWxsKGInelBJTkdcMCcpCiAgICAgICAgICAgIGlmIHNvY2sucmVjdigxMDApLnN0YXJ0c3dpdGgoYidQT05HJyk6CiAgICAgICAgICAgICAgICBicmVhawogICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgcGFzcwogICAgdGltZS5zbGVlcCgyKQplbHNlOgogICAgc3lzLmV4aXQoJ0NsYW1BViBkaWQgbm90IGJlY29tZSByZWFkeTsgcmVmdXNpbmcgdG8gc3RhcnQgT01HIEFQSScpClBZV0FJVApleGVjIC91c3IvbG9jYWwvYmluL3V2aWNvcm4gYXBwOmFwcCAtLWhvc3QgMTI3LjAuMC4xIC0tcG9ydCA4MDAwIC0tcHJveHktaGVhZGVycyAtLWZvcndhcmRlZC1hbGxvdy1pcHMgMTI3LjAuMC4xCg==' | base64 -d > /usr/local/bin/omg-start-api \
    && printf '%s' 'W3N1cGVydmlzb3JkXQpub2RhZW1vbj10cnVlCmxvZ2ZpbGU9L2Rldi9udWxsCnBpZGZpbGU9L3J1bi9zdXBlcnZpc29yZC5waWQKdXNlcj1yb290CgpbcHJvZ3JhbTpjbGFtZF0KY29tbWFuZD0vdXNyL3NiaW4vY2xhbWQKcHJpb3JpdHk9MTAKYXV0b3N0YXJ0PXRydWUKYXV0b3Jlc3RhcnQ9dHJ1ZQpzdGFydHNlY3M9NQpzdGRvdXRfbG9nZmlsZT0vZGV2L2ZkLzEKc3Rkb3V0X2xvZ2ZpbGVfbWF4Ynl0ZXM9MApzdGRlcnJfbG9nZmlsZT0vZGV2L2ZkLzIKc3RkZXJyX2xvZ2ZpbGVfbWF4Ynl0ZXM9MAoKW3Byb2dyYW06ZnJlc2hjbGFtXQpjb21tYW5kPS91c3IvYmluL2ZyZXNoY2xhbSAtLWRhZW1vbiAtLWZvcmVncm91bmQgLS1jaGVja3M9MTIKcHJpb3JpdHk9MTUKYXV0b3N0YXJ0PXRydWUKYXV0b3Jlc3RhcnQ9dHJ1ZQpzdGFydHNlY3M9MwpzdGRvdXRfbG9nZmlsZT0vZGV2L2ZkLzEKc3Rkb3V0X2xvZ2ZpbGVfbWF4Ynl0ZXM9MApzdGRlcnJfbG9nZmlsZT0vZGV2L2ZkLzIKc3RkZXJyX2xvZ2ZpbGVfbWF4Ynl0ZXM9MAoKW3Byb2dyYW06YXBpXQpkaXJlY3Rvcnk9L2FwcApjb21tYW5kPS91c3IvbG9jYWwvYmluL29tZy1zdGFydC1hcGkKcHJpb3JpdHk9MjAKYXV0b3N0YXJ0PXRydWUKYXV0b3Jlc3RhcnQ9dHJ1ZQpzdGFydHNlY3M9OApzdG9wYXNncm91cD10cnVlCmtpbGxhc2dyb3VwPXRydWUKc3Rkb3V0X2xvZ2ZpbGU9L2Rldi9mZC8xCnN0ZG91dF9sb2dmaWxlX21heGJ5dGVzPTAKc3RkZXJyX2xvZ2ZpbGU9L2Rldi9mZC8yCnN0ZGVycl9sb2dmaWxlX21heGJ5dGVzPTAKCltwcm9ncmFtOm5naW54XQpjb21tYW5kPS91c3Ivc2Jpbi9uZ2lueCAtZyAiZGFlbW9uIG9mZjsiCnByaW9yaXR5PTMwCmF1dG9zdGFydD10cnVlCmF1dG9yZXN0YXJ0PXRydWUKc3RhcnRzZWNzPTMKc3Rkb3V0X2xvZ2ZpbGU9L2Rldi9mZC8xCnN0ZG91dF9sb2dmaWxlX21heGJ5dGVzPTAKc3RkZXJyX2xvZ2ZpbGU9L2Rldi9mZC8yCnN0ZGVycl9sb2dmaWxlX21heGJ5dGVzPTAK' | base64 -d > /etc/supervisor/conf.d/omg.conf \
    && chmod 0755 /usr/local/bin/omg-entrypoint /usr/local/bin/omg-start-api

VOLUME ["/var/lib/clamav"]
# Port 443 is intentionally NOT exposed by this image: host Nginx terminates TLS.
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --start-period=180s --retries=3 CMD curl -fsS http://127.0.0.1/health || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/omg-entrypoint"]



