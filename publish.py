import paho.mqtt.client as mqtt
import paho.mqtt.client as mqtt
from meshtastic import mesh_pb2, mqtt_pb2, portnums_pb2, telemetry_pb2
import random
import time
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import json
import re
import argparse
import sys

# Default settings
MQTT_BROKER = "mqtt.meshtastic.org"
MQTT_PORT = 1883
MQTT_USERNAME = "meshdev"
MQTT_PASSWORD = "large4cats"
root_topic = "msh/ANZ/2/c/"
channel = "LongFast"
key = "1PG7OiApB1nwvP+rz05pAQ=="
node_number = 0xABCD  # Example node number, change as needed
broadcast_id = 4294967295


node_name = '!abcdc907'

# Convert hex to int and remove '!'
node_number = int(node_name.replace("!", ""), 16)


def set_topic():
    global subscribe_topic, publish_topic, node_number, node_name
    node_name = '!' + hex(node_number)[2:]
    subscribe_topic = root_topic + channel + "/#"
    publish_topic = root_topic + channel + "/" + node_name

def current_time():
    current_time_seconds = time.time()
    current_time_struct = time.localtime(current_time_seconds)
    current_time_str = time.strftime("%H:%M:%S", current_time_struct)
    return(current_time_str)

def xor_hash(data):
    result = 0
    for char in data:
        result ^= char
    return result

def generate_hash(name, key):
    replaced_key = key.replace('-', '+').replace('_', '/')
    key_bytes = base64.b64decode(replaced_key.encode('utf-8'))
    h_name = xor_hash(bytes(name, 'utf-8'))
    h_key = xor_hash(key_bytes)
    result = h_name ^ h_key
    return result


def direct_message(destination_id):
    destination_id = int(destination_id[1:], 16)
    publish_message(destination_id)


def publish_message(destination_id, message):
    global key

    if not client.is_connected():
        connect_mqtt()

    message_text = message
    if message_text:
        encoded_message = mesh_pb2.Data()
        encoded_message.portnum = portnums_pb2.TEXT_MESSAGE_APP 
        encoded_message.payload = message_text.encode("utf-8")

    generate_mesh_packet(destination_id, encoded_message)


def generate_mesh_packet(destination_id, encoded_message):
    mesh_packet = mesh_pb2.MeshPacket()

    setattr(mesh_packet, "from", node_number)
    mesh_packet.id = random.getrandbits(32)
    mesh_packet.to = destination_id
    mesh_packet.want_ack = False
    mesh_packet.channel = generate_hash(channel, key)
    mesh_packet.hop_limit = 3

    if key == "":
        mesh_packet.decoded.CopyFrom(encoded_message)
    else:
        mesh_packet.encrypted = encrypt_message(channel, key, mesh_packet, encoded_message)

    service_envelope = mqtt_pb2.ServiceEnvelope()
    service_envelope.packet.CopyFrom(mesh_packet)
    service_envelope.channel_id = channel
    service_envelope.gateway_id = node_name

    payload = service_envelope.SerializeToString()
    set_topic()
    client.publish(publish_topic, payload)


def send_node_info(destination_id):
    # NOTE THIS SECTION DOES NOT CURRENTLY WORK, NEED TO WORK OUT WHY.


    global client_short_name, client_long_name, node_name, node_number, client_hw_model, broadcast_id
    # if debug: print("send_node_info")

    if not client.is_connected():
        message =  current_time() + " >>> Connect to a broker before sending nodeinfo"
        # update_gui(message, tag="info")
    else:
        if destination_id == broadcast_id:
            message =  current_time() + " >>> Broadcast NodeInfo Packet"
            # update_gui(message, tag="info")

            # if debug: print(f"Sending NodeInfo Packet to {str(destination_id)}")

        node_number = int(node_number)
        long_name_entry = "MQTT-CLIENT"
        short_name_entry = "MQSC"
        client_hw_model = "MQTT-Soft-Client"
        decoded_client_id = bytes(node_name, "utf-8")
        decoded_client_long = bytes(long_name_entry, "utf-8")
        decoded_client_short = bytes(short_name_entry, "utf-8")
        decoded_client_hw_model = client_hw_model

        user_payload = mesh_pb2.User()
        setattr(user_payload, "id", decoded_client_id)
        setattr(user_payload, "long_name", decoded_client_long)
        setattr(user_payload, "short_name", decoded_client_short)
        setattr(user_payload, "hw_model", decoded_client_hw_model)

        user_payload = user_payload.SerializeToString()

        encoded_message = mesh_pb2.Data()
        encoded_message.portnum = portnums_pb2.NODEINFO_APP
        encoded_message.payload = user_payload
        encoded_message.want_response = True  # Request NodeInfo back

        generate_mesh_packet(destination_id, encoded_message)



def encrypt_message(channel, key, mesh_packet, encoded_message):
    mesh_packet.channel = generate_hash(channel, key)
    key_bytes = base64.b64decode(key.encode('ascii'))
    nonce_packet_id = mesh_packet.id.to_bytes(8, "little")
    nonce_from_node = node_number.to_bytes(8, "little")
    nonce = nonce_packet_id + nonce_from_node

    cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_bytes = encryptor.update(encoded_message.SerializeToString()) + encryptor.finalize()

    return encrypted_bytes

def connect_mqtt():

    global mqtt_broker, mqtt_username, mqtt_password, root_topic, channel, node_number, db_file_path, key
    if not client.is_connected():

        padded_key = key.ljust(len(key) + ((4 - (len(key) % 4)) % 4), '=')
        replaced_key = padded_key.replace('-', '+').replace('_', '/')
        key = replaced_key

        client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
        client.connect(MQTT_BROKER, MQTT_PORT, 60)

def on_connect(client, userdata, flags, reason_code, properties):
    
    set_topic()
    send_node_info(broadcast_id)


if __name__ == '__main__':
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

    client.on_connect = on_connect
    client.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWORD)
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    
    parser = argparse.ArgumentParser(description="Send a message to the MQTT server with correct encryption.")
    parser.add_argument("message", type=str, help="Message to send")
    args = parser.parse_args()

    message = args.message
    # message = "ADD YOUR MESSAGE HERE"

    publish_message(broadcast_id, message)


