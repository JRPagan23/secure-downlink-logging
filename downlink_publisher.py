import json
import paho.mqtt.client as mqtt
import ssl
import base64
import time
from crypto_utils import encrypt, generate_hmac, load_key

# Configuration
MQTT_BROKER = "localhost"
MQTT_PORT = 8884
MQTT_TOPIC = "satellite/telemetry"
CA_CERT = "certs/ca.crt"
CLIENT_CERT = "certs/client.crt"
CLIENT_KEY = "certs/client.key"
SECRET_KEY_PATH = "secret.key"

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("✅ Publisher connected with result code", rc)
    else:
        print(f"❌ Connection failed with code {rc}")

def main():
    # Load secret key
    secret_key = load_key(SECRET_KEY_PATH)

    # Setup MQTT client with TLS
    client = mqtt.Client()
    client.tls_set(ca_certs=CA_CERT, certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    client.on_connect = on_connect
    client.connect(MQTT_BROKER, MQTT_PORT)
    client.loop_start()
    time.sleep(1)

    # Interactive loop to publish telemetry
    while True:
        telemetry = input("📡 Enter telemetry to send: ").strip()
        if not telemetry:
            continue

        # Build message with timestamp
        message_dict = {
            "telemetry": telemetry,
            "timestamp": time.time()
        }

        # Serialize and encrypt
        plaintext = json.dumps(message_dict).encode()
        ciphertext, nonce, tag = encrypt(plaintext, secret_key)

        # HMAC signature
        hmac_signature = generate_hmac(plaintext, secret_key)

        # Base64-encode all parts for safe transmission
        message_payload = {
            "ciphertext": base64.urlsafe_b64encode(ciphertext).decode(),
            "nonce": base64.urlsafe_b64encode(nonce).decode(),
            "tag": base64.urlsafe_b64encode(tag).decode(),
            "hmac": base64.urlsafe_b64encode(hmac_signature).decode()
        }

        # Publish as JSON
        client.publish(MQTT_TOPIC, json.dumps(message_payload))
        print("✅ Telemetry sent securely.")

if __name__ == "__main__":
    main()
