# Project Overview

This project utilizes DPDK to efficiently process packets at high speed. It aims to provide a robust framework for packet generation, processing, and verification using various tools.

## Prerequisites

- DPDK installed on your system.
- Python 3.x for running tests and configurations.
- Access to required network permissions (e.g., sudo privileges).

## Repository Structure

```
/packet_generator  # Packet generation code
/dpdk_l3fwd     # DPDK L3 forwarding code
/tests           # Test suite with pytest
/config          # Configuration files
README.md       # Project overview and documentation
```

## Configuration

Configuration is done using a `config.yaml` file. You can also override settings using `pytest` CLI options.

### Example config.yaml

```yaml
packet_size: 64
interface: eth0
handlers:
  - type: http
    config:
      port: 80
```

### Example pytest commands

To run all tests:
```bash
pytest -v
```
To run a specific test:
```bash
pytest tests/test_packet_generation.py -v
```

## Packet Generation

Packet generation takes place in the `/packet_generator` directory. It uses the configured settings in `config.yaml` to generate packets based on the specified parameters.

## Running dpdk-l3fwd

The DPDK L3 forwarding application executes as follows:
```bash
./build/l3fwd -c ffff -n 4 -- -p 0x1
```

## Monitoring and Tracing

You can trace the DPDK application using tools such as `tcpdump` or by enabling debug logs in your configuration. To capture packets remotely using tcpdump:
```bash
tcpdump -i eth0 -w dump.pcap
```

## Verification

Verification of generated packets is done using the test suite. The tests ensure that the packets are processed as intended.

## Running Tests

### Dry-Run
To perform a dry-run of tests:
```bash
pytest --dry-run
```

### Live
To execute tests live, ensure proper network permissions are set and run:
```bash
pytest
```

## Troubleshooting Tips
- Ensure DPDK is correctly configured to access the network interface.
- Check permissions if you encounter access issues.
- Validate the config.yaml structure before running tests.

## Security/Premissions Notes
- Root privileges may be needed for running DPDK applications (use `sudo`).
- Ensure SSH access is secured and limited.
- Be cautious when using tcpdump to avoid exposing sensitive data.
- Network permissions for DPDK applications should be tightly controlled.