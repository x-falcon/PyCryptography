# -*-coding:utf-8-*-
import base64
import aes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa


def sign_by_rsa_with_sha256(key, data):
    """
    sign message with rsa with sha256
    :param key: bin
    :param data: bin
    :return: bin
    """
    privateKey = serialization.load_der_private_key(key, None, default_backend())
    return privateKey.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                           hashes.SHA256())


def verify_signature(key, signature, data):
    """

    :param key: bin
    :param signature:bin
    :param data: bin
    :return:
    """
    public_key = serialization.load_der_public_key(key, default_backend())
    try:
        public_key.verify(signature, data,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                          hashes.SHA256())
        return True
    except InvalidSignature as e:
        return False


def generate_key(key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    p1 = private_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                   encryption_algorithm=serialization.NoEncryption())
    p2 = private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    return p1, p2
