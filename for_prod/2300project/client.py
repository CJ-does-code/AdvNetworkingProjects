from cryptography import x509
import threading
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import random
import time
import networkfunction
import certgeneration_and_private
from certgeneration_and_private import ca_cert
import argparse



def client():
    parser = argparse.ArgumentParser(description="Client program to connect to a network")
    registered_names = []
    public_keys= []
    # Define expected command-line arguments
    parser.add_argument('--network', required=True, help="IP address of the network")
    parser.add_argument('--name', required=True, help="The client's name or identifier")
    args = parser.parse_args()
    print(f"Network: {args.network}")
    print(f"Client Name: {args.name}")
    key,encoded_key= certgeneration_and_private.generate_private_key()
    print(f"{encoded_key}")
    cert = certgeneration_and_private.create_signed_cert(key,"uml.edu",args.name)
    threading.Thread(target=networkfunction.start_peer_udpserver, args=(encoded_key,args.network, 8080, cert, "myCA.crt",)).start()
    networkfunction.register_server(args.network, 8080, cert, encoded_key, "myCA.crt")
    registered_names,public_keys=networkfunction.update_server(args.network, 8080, cert, encoded_key, "myCA.crt")
    while True:
        time.sleep(10)
        registered_names,public_keys=networkfunction.update_server(args.network, 8080, cert, encoded_key, "myCA.crt")
        time.sleep(5)
        networkfunction.udp_broadcast(encoded_key,public_keys,"ping",args.name)



def retrieve_lists():
    return registered_names, public_keys

client()

