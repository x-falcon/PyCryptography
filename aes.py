# -*-coding:utf-8-*-
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


def aes_ecb_decrypt(key, data, block_size=256):
    """
    decrypt aes by ecb mode
    :param key: bin
    :param data: bin
    :param block_size: key_size
    :return: bin
    """
    algorithms_ = algorithms.AES(key)
    cipher = Cipher(algorithms_, modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(block_size).unpadder()

    return  unpadder.update(decryptor.update(data))+unpadder.finalize()


def aes_ecb_encrypt(key, data, block_size=256):
    """
    decrypt aes by ecb mode
    :param key: bin
    :param data: bin
    :param block_size: key_size
    :return: bin
    """
    algorithms_ = algorithms.AES(key)
    cipher = Cipher(algorithms_, modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(block_size).padder()
    return encryptor.update(padder.update(data)+padder.finalize())
