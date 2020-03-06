# coding: utf-8
# import ConfigParser
from Crypto.Cipher import AES
from Crypto import Random
import zlib
from utils import mac_string_2_array, ip_string_2_array
from binascii import a2b_hex
from struct import pack, unpack
# import time
# import psutil
# from random import randint
# from uptime import uptime
# from tlv import UnifiTLV

def encode_inform(key, data,usecbc,mac):
    iv = Random.new().read(16)
    payload = zlib.compress(data)

    flag = 0x0B if not usecbc else 0x03
    encoded_data = 'TNBU'                     # magic
    encoded_data += pack('>I', 0)             # packet version
    encoded_data += pack('BBBBBB', *(bytearray(mac_string_2_array(mac) ) ) )  #mac
    encoded_data += pack('>H', flag)    #3         # flags
    encoded_data += iv                        # encryption iv
    encoded_data += pack('>I', 1)             # payload version

    if not usecbc:
        encoded_data += pack('>I', len(payload)+16)  # payload length
        cipher = AES.new(a2b_hex(key), AES.MODE_GCM, nonce=iv)
        cipher.update(encoded_data) #aad logic
        payload,tag = cipher.encrypt_and_digest(payload)
        payload = ''.join([payload,tag]) 
    else:    
        pad_len = AES.block_size - (len(payload) % AES.block_size)
        payload += chr(pad_len) * pad_len
        payload = AES.new(a2b_hex(key), AES.MODE_CBC, iv).encrypt(payload)
        encoded_data += pack('>I', len(payload))  # payload length

    encoded_data += payload
    return encoded_data


def decode_inform(key, encoded_data):
    magic = encoded_data[0:4]
    if magic != 'TNBU':
        raise Exception("Missing magic in response: '{}' instead of 'TNBU'".format(magic))

    flags = unpack('>H', encoded_data[14:16])[0]
    iv = encoded_data[16:32]
    version = unpack('>I', encoded_data[32:36])[0]
    payload_len = unpack('>I', encoded_data[36:40])[0]
    payload = encoded_data[40:(40+payload_len)]

    # decrypt if required
    if flags & 0x01:
        if flags & 0x08 :
            cipher = AES.new(a2b_hex(key), AES.MODE_GCM, nonce=iv)
            cipher.update(encoded_data[0:40]) #aad logic
            payload = cipher.decrypt_and_verify(payload[:-16],payload[-16:])
        else:    
            payload = AES.new(a2b_hex(key), AES.MODE_CBC, iv).decrypt(payload)
            pad_size = ord(payload[-1])
            if pad_size > AES.block_size:
                raise Exception('Response not padded or padding is corrupt')
            payload = payload[:(len(payload) - pad_size)]
    # uncompress if required
    if flags & 0x02:
        payload = zlib.decompress(payload)
    print (payload)
    return payload


