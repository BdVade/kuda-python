import xml.etree.ElementTree as ET
from Crypto.PublicKey.RSA import construct
from Crypto.Cipher import PKCS1_OAEP, AES
from base64 import b64decode
from decouple import config


def convert_to_hex_num(component):
    number = b64decode(component.encode())
    number_hex_string = "".join([f"{x:02x}" for x in number])
    return int(number_hex_string, 16)


key = config('PRIVATE')


def XMLtoRSAobject(private_key: str):
    xml = ET.fromstring(private_key)
    modulus = xml.find('Modulus').text
    exponent = xml.find('Exponent').text
    private_exponent = xml.find('D').text
    p = xml.find('P').text
    q = xml.find('Q').text
    exp_num = convert_to_hex_num(exponent)
    mod_num = convert_to_hex_num(modulus)
    p_exp_num = convert_to_hex_num(private_exponent)

    return construct((mod_num, exp_num, p_exp_num), consistency_check=True)


# rsa_key = XMLtoRSAobject(key)
# cipher_rsa = PKCS1_OAEP.new(rsa_key)
# encrypted = cipher_rsa.encrypt('laugh'.encode())
# print(cipher_rsa.decrypt(encrypted).decode())

# TODO: Figure out AES decryption
cipher = AES.new('kjdfljweriririri'.encode(), AES.MODE_EAX)
ciphertext = cipher.encrypt(b'secret data')
print(ciphertext)
cipher2 = AES.new('kjdfljweriririri'.encode(), AES.MODE_EAX)
print(cipher2.decrypt(ciphertext))

