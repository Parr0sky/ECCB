# encoding: utf-8
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from time import time
import sys
def data():
    mensaje= b"89392679556575597635196565386081702718512260749406173579320076828061414488077821523722981888265393212848183094"

    #X25519 bench
    start_time= time()
    private_key = X25519PrivateKey.generate()
    peer_public_key = X25519PrivateKey.generate().public_key()
    k255=time()-start_time
    #print("Generación llave X25519 en: " + str(k255) + " sec con tamaño: "+ str(sys.getsizeof(private_key))+" bytes")
    private_key=0

    #25519 sign
    start_time= time()
    private_key = Ed25519PrivateKey.generate()
    signature = private_key.sign(mensaje)
    s255=time()-start_time
    #print("Generación firma X25519 en: " + str(s255) + " sec")

    start_time= time()
    public_key = private_key.public_key()
    public_key.verify(signature, mensaje)
    ver255=time()-start_time
    #print("Verificación firma X25519 en: " + str(ver255) + " sec")
    private_key=0
    #448 Key Exchange
    start_time=time()
    private_key = X448PrivateKey.generate()
    peer_public_key = X448PrivateKey.generate().public_key()
    k448=time()-start_time
    #print("Generación 448 llave en: " + str(k448) + " sec con tamaño: "+ str(sys.getsizeof(private_key))+" bytes")
    private_key=0
    #448 sign

    private_key = Ed448PrivateKey.generate()
    start_time= time()
    signature = private_key.sign(mensaje)
    s448=time()-start_time
    #print("Generación 448 firma en: " + str(s448) + " sec")
    start_time=time()
    public_key = private_key.public_key()
    public_key.verify(signature, mensaje)
    ver448=time()-start_time
    #print("Verificación 448 firma en: " + str(ver448) + " sec")
    private_key=0

    #RSA GENERATION
    start_time=time()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    krsa=time()-start_time
    #print("Generación RSA llave en: " + str(krsa) + " sec con tamaño: "+ str(sys.getsizeof(private_key))+" bytes")

    #RSA SINGING
    start_time=time()
    signature = private_key.sign(
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    srsa=time()-start_time
    #print("Generación RSA firma en: " + str(srsa) + " sec")
    private_key=0
    #DSA SINGING
    start_time=time()
    private_key = dsa.generate_private_key(
        key_size=1024,
    )
    kdsa=time()-start_time
    #print("Generación DSA llave en: " + str(kdsa) + " sec con tamaño: "+ str(sys.getsizeof(private_key))+" bytes")
    start_time =time()
    signature = private_key.sign(
        mensaje,
        hashes.SHA256()
    )
    sdsa=time()-start_time
    #print("Generación DSA firma en: " + str(sdsa) + " sec")


    return [k255,s255,ver255,k448,s448,ver448,krsa,srsa,kdsa,sdsa]