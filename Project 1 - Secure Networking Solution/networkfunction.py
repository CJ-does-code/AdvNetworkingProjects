import socket
import ssl
import threading
import json
import cryptography.x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

# Allocate dynamic ports starting from 5000
def get_local_ip():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except Exception as e:
        return f"Error retrieving IP address: {e}"


def allocate_dynamic_port(x=0):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((get_local_ip(), 5000 + x))  # Start from port 5000
            return s.getsockname()[1]
        except:
            return allocate_dynamic_port(x + 1)

# Function to create SSL context with mutual authentication
def create_ssl_context(certfile, keyfile, cafile=None):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    context.verify_mode = ssl.CERT_REQUIRED
    if cafile:
        context.load_verify_locations(cafile)
    
    return context

# Handle the peer-to-peer connection
def handle_peer_connection(conn, addr, ssl_context):
    
    # Perform mutual TLS handshake
    ssl_conn = ssl_context.wrap_socket(conn, server_side=True)
    try:
        # Handle the incoming request or message
        data = ssl_conn.recv(1024)
        if data:
            print(f"Received data: {data.decode()}")
    except ssl.SSLError as e:
        print(f"SSL Error: {e}")
    finally:
        ssl_conn.close()

# Start a peer server to listen for incoming connections
def start_peer_udpserver(private_key_path,peer_ip, peer_port, certfile, cafile):
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) # create client to communicate with the UDP server
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverAddress = "0.0.0.0"#listen on all interfaces
    serverAddress = ("0.0.0.0",12345)  # Listen on all interfaces and a specified port
    serverSocket.bind(serverAddress)

    while True:
        
        data, address = serverSocket.recvfrom(4096)
        sign, address = serverSocket.recvfrom(4096)  # 4096 bytes buffer size
        with open(private_key_path, 'rb') as private_key_file:
            private_key = serialization.load_pem_private_key(
                private_key_file.read(),
                password=None, 
                backend=default_backend()
            )
        try:
            #dodgey method but should work makes a little bit more tedious

            people_list, keys=update_server(peer_ip, peer_port, certfile, private_key_path, cafile)
            decrypted_message = private_key.decrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            dec=decrypted_message.decode('utf-8')
            print(f"{dec}")
            
            parts = dec.split('||')
            index = people_list.index(parts[0])
            senders = serialization.load_pem_public_key(keys[index])
            try:
                print("unverified")
                public_key.verify(sign,decrypted_message,padding.PKCS1v15(),hashes.SHA256())
                print("verified")
            except Exception as e:
                print("bad signiture")
            response_message = "pong"  # Response message can be customized as needed
            serverSocket.sendto(response_message.encode('utf-8'), address)
            print(f"Sent response: {response_message} to {address}")
        except Exception as e:
            x=1

def Server_start(certfile, keyfile, cafile,people,keys):
    # Dynamically allocate a port
    port = 8080
    print(f"server starting on port {get_local_ip()}::8080...")

    # Create SSL context for mutual authentication
    ssl_context = create_ssl_context( certfile,keyfile,"myCA.crt")

    # Bind and listen for incoming connections
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((get_local_ip(), port))
        s.listen(5)

        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client_connection, args=(conn, addr, ssl_context,people,keys)).start()

def handle_client_connection(conn, addr, ssl_context,people,keys):
   # Perform mutual TLS handshake
    ssl_conn = ssl_context.wrap_socket(conn, server_side=True)
    client_cert = ssl_conn.getpeercert()
    try:
        # Handle the incoming request or message
        data = ssl_conn.recv(4096)
        text = data.decode('utf-8')
        if text == "register":
            client_name = client_cert['subject'][-1][0][1]
            pubkey = client_cert['subject'][2][0][1]
            print(f"registered {client_name}")
            people.append(client_name)
            keys.append(pubkey)
        elif text == "update":
            response = {"people": people,"keys": keys}
            response_json = json.dumps(response).encode('utf-8')
            ssl_conn.sendall(response_json)


            
    except ssl.SSLError as e:
        print(f"SSL Error: {e}")
    finally:
        ssl_conn.close()

# Connect to server
def register_server(peer_ip, peer_port, certfile, keyfile, cafile=None):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((peer_ip, peer_port))

     # Configure SSL/TLS context for the client
    context = create_ssl_context(certfile, keyfile, cafile)
    secure_client_socket = context.wrap_socket(client_socket, server_side=False, server_hostname=get_local_ip())

    # Send the "online" message to the server
    secure_client_socket.send(b"register")


def update_server(peer_ip, peer_port, certfile, keyfile, cafile):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((peer_ip, peer_port))

     # Configure SSL/TLS context for the client
    context = create_ssl_context(certfile, keyfile, cafile)
    secure_client_socket = context.wrap_socket(client_socket, server_side=False, server_hostname=get_local_ip())

    # Send the "online" message to the server
    secure_client_socket.send(b"update")
    received_data = secure_client_socket.recv(4096)
    decoded_data = received_data.decode('utf-8')
    data_dict = json.loads(decoded_data)
    
    people_list = data_dict.get("people", [])
    keys = data_dict.get("keys", [])
    return people_list, keys

def udp_broadcast(private_key_path, public_keys, message,name, port=12345):
    # Create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    for item in public_keys:

        recipient_public_key = serialization.load_pem_public_key(item.encode())
        unencrypted=name+"||"+message
        signiture = private_key.sign(
            unencrypted.encode('utf-8'),
            padding.PKCS1v15(),  
            hashes.SHA256()
        )
        
        second_uncrypted=unencrypted
        final=recipient_public_key.encrypt(
            second_uncrypted.encode('utf-8'),  # The signed message we want to encrypt
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # OAEP padding
                algorithm=hashes.SHA256(),  # Hash algorithm
                label=None
            )
        )
        # Set the broadcast address
        broadcast_address = ('<broadcast>', port)
        
        # Send the message
        udp_socket.sendto(final, broadcast_address)
        udp_socket.sendto(signiture, broadcast_address)
        # Receive response (acknowledgment)
        udp_socket.settimeout(2)  # Set a timeout for waiting for a response (2 seconds)
        try:
            response, address = udp_socket.recvfrom(4096)

            print(f"Received response from {address}: {response.decode('utf-8')}")
        except socket.timeout:
            print("No response received from peer.")

        # Close the socket
    udp_socket.close()


