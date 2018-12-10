# -*-coding:utf-8-*-
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def sign_with_sha256(key, data):
    """
    sign message with rsa with sha256
    :param key: bin
    :param data: bin
    :return: bin
    """
    privateKey = serialization.load_der_private_key(key, None, default_backend())
    return privateKey.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_signature(key, signature, data):
    """

    :param key: bin
    :param signature:bin
    :param data: bin
    :return:
    """
    public_key = serialization.load_der_public_key(key, default_backend())
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature as e:
        return False


def generate_key(curve=ec.SECP256K1):
    private_key = ec.generate_private_key(curve(), backend=default_backend())
    p1 = private_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                   encryption_algorithm=serialization.NoEncryption())
    p2 = private_key.public_key().public_bytes(serialization.Encoding.DER,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
    return p1, p2


if __name__ == '__main__':
    print(generate_key())
