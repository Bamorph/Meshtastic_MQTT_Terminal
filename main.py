#!/usr/bin/env python3

import paho.mqtt.client as mqtt
from meshtastic import mesh_pb2, mqtt_pb2, portnums_pb2, telemetry_pb2

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import random

from plyer import notification


# Default settings
MQTT_BROKER = "mqtt.meshtastic.org"
MQTT_PORT = 1883
MQTT_USERNAME = "meshdev"
MQTT_PASSWORD = "large4cats"
root_topic = "msh/ANZ/2/c/"
channel = "LongFast"
key = "1PG7OiApB1nwvP+rz05pAQ=="

broadcast_id = 4294967295

# Convert hex to int and remove '!'
node_number = int('abcd', 16)

def process_message(mp, text_payload, is_encrypted):

    text = {
        "message": text_payload,
        "from": getattr(mp, "from"),
        "id": getattr(mp, "id"),
        "to": getattr(mp, "to")
    }

    notification.notify(
    title = f"{getattr(mp, 'from')}",
    message = f"{text_payload}",
    timeout = 10
    )
    print(text)

def decode_encrypted(message_packet):
    try:
        key_bytes = base64.b64decode(key.encode('ascii'))
      
        nonce_packet_id = getattr(message_packet, "id").to_bytes(8, "little")
        nonce_from_node = getattr(message_packet, "from").to_bytes(8, "little")
        nonce = nonce_packet_id + nonce_from_node

        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(getattr(message_packet, "encrypted")) + decryptor.finalize()

        data = mesh_pb2.Data()
        data.ParseFromString(decrypted_bytes)
        message_packet.decoded.CopyFrom(data)
        
        if message_packet.decoded.portnum == portnums_pb2.TEXT_MESSAGE_APP:
            text_payload = message_packet.decoded.payload.decode("utf-8")
            is_encrypted = True
            process_message(message_packet, text_payload, is_encrypted)
            print(f"{text_payload}")


        elif message_packet.decoded.portnum == portnums_pb2.NODEINFO_APP:
                info = mesh_pb2.User()
                info.ParseFromString(message_packet.decoded.payload)
                print(info)
                # notification.notify(
                # title = "Meshtastic",
                # message = f"{info}",
                # timeout = 10
                # )
        elif message_packet.decoded.portnum == portnums_pb2.POSITION_APP:
            pos = mesh_pb2.Position()
            pos.ParseFromString(message_packet.decoded.payload)
            print(pos)

        elif message_packet.decoded.portnum == portnums_pb2.TELEMETRY_APP:
            env = telemetry_pb2.Telemetry()
            env.ParseFromString(message_packet.decoded.payload)
            print(env)

    except Exception as e:
        print(f"Decryption failed: {str(e)}")

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"Connected to {MQTT_BROKER} on topic {channel}")
    else:
        print(f"Failed to connect to MQTT broker with result code {str(rc)}")

def on_message(client, userdata, msg):
    service_envelope = mqtt_pb2.ServiceEnvelope()
    try:
        service_envelope.ParseFromString(msg.payload)
        # print(service_envelope)
        message_packet = service_envelope.packet
        # print(message_packet)
    except Exception as e:
        print(f"Error parsing message: {str(e)}")
        return
    
    if message_packet.HasField("encrypted") and not message_packet.HasField("decoded"):
        decode_encrypted(message_packet)

if __name__ == '__main__':
    client = mqtt.Client(client_id="", clean_session=True, userdata=None)
    client.on_connect = on_connect
    client.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWORD)
    client.connect(MQTT_BROKER, MQTT_PORT, 60)

    client.on_message = on_message

    subscribe_topic = f"{root_topic}{channel}/#"

    client.subscribe(subscribe_topic, 0)

    while client.loop() == 0:
        pass
