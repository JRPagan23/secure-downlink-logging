Secure Downlink & Logging

This project simulates a secure satellite telemetry downlink system using MQTT with TLS encryption. It ensures confidentiality, integrity, and logging of satellite data received by ground stations.

Features

MQTT over TLS for encrypted communication

AES-GCM encryption for payload confidentiality

HMAC verification for message integrity

Timestamp-based replay attack prevention

Telemetry log file with human-readable entries

How It Works

Publisher (Satellite) encrypts telemetry with AES-GCM, signs it with HMAC, and sends it over MQTT.

Subscriber (Ground Station) verifies HMAC, decrypts the message, checks timestamp, and logs the telemetry.

Project Structure

secure-downlink-logging/
├── certs/                  # TLS certificates
├── crypto_utils.py         # Encryption and HMAC utilities
├── downlink_publisher.py   # Sends encrypted telemetry
├── downlink_subscriber.py  # Receives and decrypts telemetry
├── telemetry.log           # Securely logs received messages
├── generate_key.py         # Generates AES key (base64)
└── mosquitto_tls.conf      # Mosquitto TLS configuration

️Security Mechanisms

Encryption: AES-GCM using a 256-bit symmetric key

Integrity: HMAC-SHA256

Transport Security: TLS with server/client certificates

Replay Protection: Timestamp comparison (reject if > 5s old)

How to Run

1. Start Mosquitto

mosquitto -c mosquitto_tls.conf

2. Start Subscriber

python3 downlink_subscriber.py

3. Start Publisher & Send Messages

python3 downlink_publisher.py

Then type telemetry like:

>root
>shutdown
>rotate

📜 Sample Log Output

[2025-07-03 19:42:01] 🔒 Received Secure Telemetry: root
[2025-07-03 19:42:10] 🔒 Received Secure Telemetry: shutdown
[2025-07-03 19:42:20] 🔒 Received Secure Telemetry: rotate

Future Improvements

Periodic key rotation

Signature verification for OTA firmware

Log encryption and backup

Skills Demonstrated

TLS and Certificate-based Authentication

Symmetric Encryption (AES-GCM)

Hash-Based Message Authentication Codes (HMAC)

Secure Protocol Design

Python MQTT Integration

Project Context

This is Project 4 in a 6-part series focused on satellite cybersecurity systems. Previous projects built up secure telemetry and command links. This one logs telemetry safely. The next project adds secure over-the-air firmware updates.

Author

Jorge Rodriguez Pagan
https://github.com/jrpagan23/secure-downlink-logging

License

MIT License
