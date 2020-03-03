# coding: utf-8
import ConfigParser
from Crypto.Cipher import AES
from Crypto import Random
import zlib
import time
import psutil
from random import randint
from struct import pack, unpack
from binascii import a2b_hex
from uptime import uptime
from tlv import UnifiTLV
from tools import mac_string_2_array, ip_string_2_array

def encode_inform(config, data):
    iv = Random.new().read(16)
    print (data)
    flag = 0x0b
    if config.has_section('mgmt_cfg') and config.has_option('mgmt_cfg','use_aes_gcm') and config.getboolean('mgmt_cfg','use_aes_gcm'):
       payload = zlib.compress(data)
       payload,tag = AES.new(a2b_hex(config.get('gateway', 'key')), AES.MODE_GCM, nonce=iv).encrypt_and_digest(payload)
       payload = ''.join([payload,tag])

       #payload = ''.join([payload,tag])
    else:    
        payload = zlib.compress(data)
        pad_len = AES.block_size - (len(payload) % AES.block_size)
        payload += chr(pad_len) * pad_len
        payload = AES.new(a2b_hex(config.get('gateway', 'key')), AES.MODE_CBC, iv).encrypt(payload)
        flag = 0x03



    encoded_data = 'TNBU'                     # magic
    encoded_data += pack('>I', 0)             # packet version
    encoded_data += pack('BBBBBB', *(bytearray(mac_string_2_array(config.get('gateway', 'lan_mac')) ) ) )  # mac address 00:26:4a:08:d6:0c //bytearray(mac_string_2_array(lan_mac))
    encoded_data += pack('>H', flag)    #3         # flags
    encoded_data += iv                        # encryption iv
    encoded_data += pack('>I', 1)             # payload version
    encoded_data += pack('>I', len(payload))  # payload length
    encoded_data += payload

    return encoded_data


def decode_inform(config, encoded_data):
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
        if flags>3 and  config.has_section('mgmt_cfg') and config.has_option('mgmt_cfg','use_aes_gcm') and config.getboolean('mgmt_cfg','use_aes_gcm'):
            payload = AES.new(a2b_hex(config.get('gateway', 'key')), AES.MODE_GCM, nonce=iv).decrypt(payload[:-16])
        else:    
            payload = AES.new(a2b_hex(config.get('gateway', 'key')), AES.MODE_CBC, iv).decrypt(payload)
            pad_size = ord(payload[-1])
            if pad_size > AES.block_size:
                raise Exception('Response not padded or padding is corrupt')
            payload = payload[:(len(payload) - pad_size)]
    # uncompress if required
    if flags & 0x02:
        payload = zlib.decompress(payload)
    print (payload)
    return payload

