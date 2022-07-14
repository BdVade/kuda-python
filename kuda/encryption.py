import rsa
from utils import XMLtoRSAobject
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes


# TODO: Decide if to use a global state object in constructor or generate new one evertime for AES
class Encryption:

    def __init__(self, xml_private_key, client_key):
        self.rsa_object = XMLtoRSAobject(xml_private_key)
        self.cipher_rsa = PKCS1_OAEP.new(self.rsa_object)
        random_bytes = get_random_bytes(31-len(client_key))
        password = client_key+'-'.encode() + random_bytes
        self.cipher_aes = AES.new(password, AES.MODE_EAX)

    def rsa_encrypt(self, plain_text):
        return self.cipher_rsa.encrypt(plain_text.encode())

    def aes_encrypt(self, key):
        cipher = AES.new(key, AES.MODE_EAX)
        # ciphertext = cipher.encrypt(data)



