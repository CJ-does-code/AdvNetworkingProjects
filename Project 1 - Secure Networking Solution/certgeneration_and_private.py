from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import random

# Load the CA certificate and private key from files
with open("myCA.key", "rb") as f:
    ca_private_key_pem = f.read()

with open("myCA.crt", "rb") as f:
    ca_cert_pem = f.read()
Ca_key= serialization.load_pem_private_key(ca_private_key_pem,password=None)
ca_cert=x509.load_pem_x509_certificate(ca_cert_pem)

def string_to_cert(str_cert):
    return x509.load_pem_x509_certificate(str_cert.encode('utf-8'))



def string_to_key(str_key):
    return serialization.load_pem_private_key(str_key.encode('utf-8'),password=None)


def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    new_key="./certskeys/private_key"+str(random.randint(1, 10000000))+".pem"
    with open(new_key, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    return private_key, new_key


def create_signed_cert(private_key,email, peer_name):
    pem = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    pem_str = pem.decode('utf-8')
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Massachusetts"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, pem_str),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, email),
        x509.NameAttribute(NameOID.COMMON_NAME, peer_name),
    ])
    
    issuer = ca_cert.subject
    
    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(private_key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.utcnow())\
        .not_valid_after(datetime.utcnow() + timedelta(days=365))\
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(peer_name)]),
            critical=False,
        )\
        .sign(Ca_key, hashes.SHA256())
    
        
    new_key="./certskeys/cert"+str(random.randint(1, 10000000))+".pem"
    with open(new_key, "wb") as f:
         f.write(cert.public_bytes(serialization.Encoding.PEM))
    return new_key


# Example usage:

# Load the CA certificate and private key from files


