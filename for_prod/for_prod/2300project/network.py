from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import random
import networkfunction
import certgeneration_and_private
from certgeneration_and_private import ca_cert
registered_names = []
public_keys= []
def basenet():
    key,encoded_key= certgeneration_and_private.generate_private_key()
    cert = certgeneration_and_private.create_signed_cert(key,"uml.edu","server")
    networkfunction.Server_start(cert,encoded_key,ca_cert,registered_names,public_keys)
    
    

basenet()






