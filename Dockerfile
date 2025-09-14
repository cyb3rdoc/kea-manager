FROM alpine:latest

LABEL author="cyb3rdoc" maintainer="cyb3rdoc@proton.me"

# Install KEA DHCP and Python
RUN apk add --no-cache \
    kea \
    kea-dhcp4 \
    kea-ctrl-agent \
    python3 \
    py3-flask \
    py3-werkzeug \
    supervisor

# Create kea user
RUN adduser -D -u 1000 kea 2>/dev/null || true && \
    mkdir -p /var/lib/kea /var/log/kea /run/kea /etc/kea && \
    chown -R kea:kea /var/lib/kea /var/log/kea /run/kea

# Copy application files
COPY app/ /app/
COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY config/kea-dhcp4.conf /etc/kea/kea-dhcp4.conf.default
COPY entrypoint.sh /entrypoint.sh

# Set permissions
RUN chmod +x /entrypoint.sh && \
    chown -R kea:kea /app

ENV TZ=UTC
VOLUME ["/etc/kea"]
EXPOSE 67/udp 5000

ENTRYPOINT ["/entrypoint.sh"]
