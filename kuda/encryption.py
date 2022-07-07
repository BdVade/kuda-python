import rsa
from .utils import XMLtoPEM


class BaseEncryption:

    def __init__(self, private_key, public_key):
        private_key = XMLtoPEM(private_key)
    #     TODO: check how to get the private key from a rsakey object get it, and assign it to attributes(self.etc)

    def encrypt(self,):
        pass

    def decrypt(self,):
        pass


class RSAEncryption(BaseEncryption):

    def encrypt(self,):
        pass

    def decrypt(self,):
        pass


class AES256Encryption(BaseEncryption):

    def encrypt(self,):
        pass
