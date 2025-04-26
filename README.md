# Velociraptor Syslog Monitor

A Python-based monitoring system that listens for Velociraptor audit logs via syslog and sends email notifications about important user actions.

## Overview

This tool monitors Velociraptor's syslog messages for specific actions performed by users within the Velociraptor DFIR platform. When certain patterns are detected, it sends detailed email notifications to designated recipients, providing enhanced visibility into user activities and potential security events.

## Features

- **Real-time monitoring**: Listens for Velociraptor audit logs via UDP syslog (default port 514)
- **Comprehensive activity detection**: Monitors numerous critical user actions including:
  - PowerShell and CMD command execution
  - Host quarantine/isolation actions (application and removal)
  - Hunt creation, execution, cancellation, and deletion
  - Client label management
  - Directory traversal (normal and NTFS)
  - Recursive directory operations
  - Recursive file downloads
  - Registry access
  - Artifact management (creation and deletion)
  - User account management
  - Organization creation
  - Password resets
  - And more...
- **Detailed email notifications**: Sends formatted notifications with relevant context for each detected event
- **Flexible configuration**: Command-line options for customizing behavior
- **Multi-threading**: Separate threads for log collection and processing
- **Comprehensive logging**: Debug and info level logs for troubleshooting

## Requirements

- Python 3.6+
- Active Velociraptor server installation
- **Velociraptor syslog configuration**: The Velociraptor server must have syslog configured to forward `VelociraptorAudit` messages to the host where this script runs
- SMTP server for sending email notifications

## Installation

1. Clone this repository:
```bash
git clone https://github.com/DrPwner/Velociraptor-Syslog.git
cd Velociraptor-Syslog
```

2. Install any required Python dependencies (standard library only)

## Velociraptor Configuration

In your Velociraptor `server.config.yaml` file, ensure that syslog is properly configured:

```yaml
Logging:
  # ... other logging configurations ...
  output_directory: /opt/velociraptor/logs
  separate_logs_per_component: true
  remote_syslog_server: 10.2.1.22:514
  remote_syslog_protocol: "udp"
  remote_syslog_components:
  - VelociraptorAudit
```

**Important:** Only forward `VelociraptorAudit` syslog messages to this service. The script is designed to parse and process these specific messages.

## Usage

Run the script with the required parameters:

```bash
python velociraptor-syslog.py \
  --smtp-server smtp.example.com \
  --smtp-port 587 \
  --sender-email alerts@example.com \
  --sender-password "your-password" \
  --recipient-email security-team@example.com
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--host` | Host IP to listen on | `0.0.0.0` |
| `--port` | UDP port to listen on | `514` |
| `--smtp-server` | SMTP server hostname | Required |
| `--smtp-port` | SMTP server port | `587` |
| `--sender-email` | Email address to send from | Required |
| `--sender-password` | Password for sender email | Required |
| `--recipient-email` | Email address to send notifications to | Required |
| `--no-tls` | Disable TLS for SMTP connection | TLS enabled by default |
| `--test` | Run in test mode with sample messages | Disabled by default |
| `--debug` | Enable debug logging | Info level by default |

## Test Mode

The script includes a test mode that can be used to validate functionality without an active Velociraptor instance:

```bash
python velociraptor-syslog.py --test \
  --smtp-server smtp.example.com \
  --smtp-port 587 \
  --sender-email alerts@example.com \
  --sender-password "your-password" \
  --recipient-email security-team@example.com
```

This requires a file named `velociraptor-syslog-key-logs.txt` in the same directory with sample log messages.

## Event Notifications

The script sends tailored email notifications for each detected event type. Examples include:

- `User admin executed "whoami" command through "CMD Shell" on endpoint "C.1234abcd" on 2023-04-26T14:35:22+00:00`
- `User analyst Quarantined the following endpoint(s): C.5678efgh on 2023-04-26T15:12:03+00:00`
- `User admin Created a hunt "Windows.System.ProcessListing" (H.ABCD1234), with a title of "Daily Process Hunt" and a description of "Collection of all running processes" on "root" org on 2023-04-26T09:15:43+00:00`

## Production Deployment

For production use, consider:

1. Running as a system service (systemd)
2. Using environment variables or a secure password store instead of command-line password parameters
3. Implementing log rotation for the log file
4. Setting up proper firewall rules to restrict UDP port access

## Security Considerations

- The script listens on UDP port 514 by default, which is a privileged port (below 1024)
- Running with root/administrator privileges may be required for binding to this port
- Consider network segmentation to prevent unauthorized access to the syslog port
- Email credentials are specified on the command line, which may be visible in process listings

## Why?

Creating Wazuh decoders was a pain in the behind area, so like any cyber head, I just built a program that does the job from scratch.

Hope it helps someone out there.

## License

[MIT License](LICENSE)
