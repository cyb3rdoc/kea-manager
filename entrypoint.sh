#!/bin/sh

# Create and set permissions for KEA runtime directory
mkdir -p /run/kea /var/log/supervisor
chmod 750 /run/kea
chown kea:kea /run/kea

# Copy default config if none exists
if [ ! -f "/etc/kea/kea-dhcp4.conf" ]; then
    echo "No configuration found, copying default..."
    cp /etc/kea/kea-dhcp4.conf.default /etc/kea/kea-dhcp4.conf
    chown kea:kea /etc/kea/kea-dhcp4.conf
fi

# Validate configuration
echo "Validating KEA DHCP4 configuration..."
kea-dhcp4 -t /etc/kea/kea-dhcp4.conf

if [ $? -ne 0 ]; then
    echo "ERROR: Configuration validation failed"
    echo "Using default configuration..."
    cp /etc/kea/kea-dhcp4.conf.default /etc/kea/kea-dhcp4.conf
    chown kea:kea /etc/kea/kea-dhcp4.conf
fi

echo "Starting services with supervisor..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
