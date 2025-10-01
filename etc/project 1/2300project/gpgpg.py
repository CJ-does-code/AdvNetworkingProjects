import socket
import ssl
import threading

def allocate_dynamic_port(x=0):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('localhost', 5000 + x))
            return s.getsockname()[1]
        except:
            return allocate_dynamic_port(x + 1)

def create_ssl_context(certfile, keyfile, cafile, client_side=False):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    context.verify_mode = ssl.CERT_REQUIRED

    if cafile:
        context.load_verify_locations(cafile)
    else:
        raise ValueError("CA file is required for mutual TLS authentication.")

    return context

def handle_peer_connection(conn, addr, ssl_context):
    try:
        print(f"[SERVER] Connection established with {addr}")
        ssl_conn = ssl_context.wrap_socket(conn, server_side=True)

        data = ssl_conn.recv(1024)
        if data:
            print(f"[SERVER] Received: {data.decode()}")
            ssl_conn.sendall(b'Hello from server!')
    except ssl.SSLError as e:
        print(f"[SERVER] SSL Error: {e}")
    except Exception as e:
        print(f"[SERVER] Unexpected error: {e}")
    finally:
        ssl_conn.close()

def start_peer_server(certfile, keyfile, cafile):
    port = allocate_dynamic_port()
    print(f"[SERVER] Listening on port {port}...")

    ssl_context = create_ssl_context(certfile, keyfile, cafile)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', port))
        s.listen(5)

        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_peer_connection, args=(conn, addr, ssl_context)).start()

def connect_to_peer(peer_ip, peer_port, certfile, keyfile, cafile):
    print(f"[CLIENT] Connecting to {peer_ip}:{peer_port}...")

    ssl_context = create_ssl_context(certfile, keyfile, cafile)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((peer_ip, peer_port))
        ssl_conn = ssl_context.wrap_socket(s, server_side=False)

        ssl_conn.sendall(b'Hello from client!')
        data = ssl_conn.recv(1024)
        print(f"[CLIENT] Received: {data.decode()}")
        ssl_conn.close()

if __name__ == "__main__":
    server_certfile = 'server_cert.pem'
    server_keyfile = 'server_key.pem'
    client_certfile = 'client_cert.pem'
    client_keyfile = 'client_key.pem'
    ca_certfile = 'ca_cert.pem'

    server_thread = threading.Thread(target=start_peer_server, args=(server_certfile, server_keyfile, ca_certfile))
    server_thread.start()

    import time
    time.sleep(1)

    peer_port = allocate_dynamic_port(-1)
    connect_to_peer('localhost', peer_port, client_certfile, client_keyfile, ca_certfile)
