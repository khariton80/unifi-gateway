# -*- coding: utf-8 -*-
import base64
import json
from struct import *

import zlib
from Crypto.Cipher import AES
from binascii import a2b_hex
#from flask import Flask, request

from inform import packet_decode,packet_encode

from Crypto.Cipher import AES
import binascii
from aes_gcm import AES_GCM

data="\x54\x4e\x42\x55\x00\x00\x00\x00\x78\x8a\x20\xdc\x43\x89\x00\x09" 
data=data+"\x54\x23\xcc\x64\xb1\xb7\x7a\x45\xfb\x41\x4c\xd2\xd9\x47\xd6\x5c" 
data=data+"\x00\x00\x00\x01\x00\x00\x00\x60\xc4\xff\x7d\xb4\xd2\x86\x35\xa3" 
data=data+"\xe6\xcd\xe5\x5e\xb1\x80\xec\x83\x2f\x76\xde\x37\x07\xd4\xf5\x17" 
data=data+"\x0e\x7a\x62\xf3\x09\xcd\x56\x70\x79\x8b\x5c\x13\x81\x25\x14\xcd" 
data=data+"\xec\x6f\xe2\xa7\x75\x18\xf1\xa0\x63\x0c\xa8\x13\xd6\xb5\x90\xd9" 
data=data+"\x2c\x18\x8a\x30\x2e\x3c\xcf\x9d\xe0\x26\xfb\x4d\x6c\x57\x3a\x7f" 
data=data+"\xe7\x2f\x78\x39\x40\x30\x56\x4d\x87\x12\x7b\xd4\xa7\x35\xc1\x45" 
data=data+"\xeb\xf3\x68\x72\x91\xd0\xcd\xe7"

payload,iv = packet_decode(a2b_hex("EE44CCE96733A3F8207F19EEB0813C57"), data)
j = json.loads(payload)
print(j)
dataa=  packet_encode(a2b_hex("EE44CCE96733A3F8207F19EEB0813C57"), payload,iv)
print(binascii.hexlify(dataa))


test_gcm = AES_GCM(0xEE44CCE96733A3F8207F19EEB0813C57)
encrypted, tag = test_gcm.encrypt(
            0x5423cc64b1b77a45fb414cd2d947d65c,
            '{"_type":"noop","interval":5,"immediate":1,"server_time_in_utc":"1583250501857"}',
            ''
        )

