import json
import paho.mqtt.client as mqtt
import ssl
import base64
import time
from datetime import datetime
from crypto_utils import decrypt, verify_hmac, load_key

# Configuration
MQTT_BROKER = "localhost"
MQTT_PORT = 8884
MQTT_TOPIC = "satellite/telemetry"
CA_CERT = "certs/ca.crt"
CLIENT_CERT = "certs/client.crt"
CLIENT_KEY = "certs/client.key"
SECRET_KEY_PATH = "secret.key"
TELEMETRY_LOG = "telemetry.log"
REPLAY_WINDOW = 5  # seconds

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("✅ Subscriber connected to broker.")
        client.subscribe(MQTT_TOPIC)
    else:
        print(f"❌ Connection failed with code {rc}")

def on_message(client, userdata, msg):
    try:
        secret_key = userdata["secret_key"]

        # Parse the incoming MQTT payload as JSON
        payload = json.loads(msg.payload.decode())

        # Ensure the message contains all expected fields
        if not all(k in payload for k in ("ciphertext", "nonce", "tag", "hmac")):
            print("⚠️ Incomplete message received.")
            return

        ciphertext = base64.urlsafe_b64decode(payload["ciphertext"])
        nonce = base64.urlsafe_b64decode(payload["nonce"])
        tag = base64.urlsafe_b64decode(payload["tag"])
        hmac_signature = base64.urlsafe_b64decode(payload["hmac"])

        # Decrypt
        decrypted_bytes = decrypt(ciphertext, nonce, tag, secret_key)

        # Verify HMAC
        if not verify_hmac(hmac_signature, decrypted_bytes, secret_key):
            print("❌ HMAC verification failed.")
            return

        # Deserialize decrypted JSON message
        message_obj = json.loads(decrypted_bytes.decode())
        timestamp = message_obj.get("timestamp")
        telemetry = message_obj.get("telemetry")

        # Replay protection
        if not timestamp or abs(time.time() - timestamp) > REPLAY_WINDOW:
            print("⚠️ Replay attack or delayed message detected.")
            return

        # Log the message
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp_str}] 🔒 Telemetry received: {telemetry}\n"
        with open(TELEMETRY_LOG, "a") as f:
            f.write(log_entry)
        print(log_entry.strip())

    except json.JSONDecodeError:
        print("❌ Error: Malformed JSON received.")
    except Exception as e:
        print(f"❌ Error processing message: {e}")

def main():
    secret_key = load_key(SECRET_KEY_PATH)
    client = mqtt.Client(userdata={"secret_key": secret_key})
    client.tls_set(ca_certs=CA_CERT, certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_BROKER, MQTT_PORT)
    client.loop_forever()

if __name__ == "__main__":
    main()

