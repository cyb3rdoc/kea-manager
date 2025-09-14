# KEA DHCP Manager

A web-based management interface for ISC KEA DHCP4 server, packaged as a lightweight Docker container.

## Features

- **Web UI Management**: Modern, responsive web interface for KEA DHCP configuration
- **Subnet Management**: Add, delete, and configure DHCP subnets with pools and options
- **Static Reservations**: Manage MAC-to-IP static reservations
- **Lease Monitoring**: View active DHCP leases in real-time
- **Configuration Editor**: Direct JSON configuration editing with validation
- **Secure Authentication**: SQLite-based user management with password reset functionality
- **Service Control**: Restart KEA DHCP service from the web interface

## Quick Start

### Using Docker

```bash
# Pull and run the container
docker run -d \
  --name kea-manager \
  --hostname kea-manager \
  --network host \
  -e TZ=UTC \
  --restart always \
  cyb3rdoc/kea-manager:latest
```

### Using Docker Compose

```yaml
services:
  kea-manager:
    image: cyb3rdoc/kea-manager:latest
    container_name: kea-manager
    hostname: kea-manager
    network_mode: host
    environment:
      - TZ=UTC
    restart: always
```

## Initial Setup

1. Access the web interface at `http://localhost:5000`
2. Complete the initial setup by creating an admin account
3. Configure your first DHCP subnet and pool
4. Start the KEA DHCP service

## Configuration

The container exposes `/etc/kea` as a volume where all configuration files are stored:

- `kea-dhcp4.conf` - Main KEA DHCP configuration
- `auth.db` - User authentication database
- `password_reset.key` - Temporary password reset keys

## Password Recovery

If you forget your admin credentials:

1. Access the container: `docker exec -it kea-manager sh`
2. Generate a reset key from the web UI ("Forgot Password")
3. Read the reset key: `cat /etc/kea/password_reset.key`
4. Use the key in the web interface to reset both username and password

## Network Configuration

**Host networking is strongly recommended** for DHCP servers because:

- DHCP relies on broadcast packets that may not work properly with Docker's bridge networking
- Direct access to network interfaces is required for proper DHCP relay and client discovery
- Eliminates potential issues with DHCP packet forwarding and NAT

Access the web interface at `http://HOST_IP:5000` when using host networking.

## Ports

When using host networking, these ports are exposed directly on the host:

- `5000/tcp` - Web management interface
- `67/udp` - DHCP server port

## Environment Variables

- `TZ` - Timezone (default: UTC)
- `SECRET_KEY` - Flask session secret (auto-generated if not provided)

## Building from Source

```bash
git clone <repository-url>
cd kea-manager
docker build -t kea-manager .
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Support

For issues and questions, please use the GitHub Issues page.
