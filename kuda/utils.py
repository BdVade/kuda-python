import xml.etree.ElementTree as ET
from Crypto.PublicKey.RSA import construct
from base64 import b64decode


def XMLtoPEM(private_key):
    xml = ET.fromstring(private_key)
    modulus = xml.find('Modulus').text
    exponent = xml.find('Exponent').text
    p = xml.find('P').text
    q = xml.find('Q').text
    mod_b64 = b64decode(modulus.encode())
    exp_b64 = b64decode(exponent.encode())
    p_b64 = b64decode(p.encode())
    q_b64 = b64decode(q.encode())
    exp = ''.join(['{:02x}'.format(x) for x in exp_b64])
    mod = ''.join(['{:02x}'.format(x) for x in mod_b64])
    new_p = ''.join(['{:02x}'.format(x) for x in p_b64])
    new_q = ''.join(['{:02x}'.format(x) for x in q_b64])
    exp_num = int(exp, 16)
    mod_num = int(mod, 16)

    return construct((mod_num, exp_num, exp_num), consistency_check=True)


