import base64
import json
import struct

import zlib
from Crypto.Cipher import AES
from binascii import a2b_hex
from flask import Flask, request

from inform import packet_decode

app = Flask(__name__)


@app.route("/inform", methods=['POST'])
def inform():
    data = request.get_data()

    payload = json.loads(packet_decode(a2b_hex("9d6d6e8a16f4bb00f65f65857666c318"), data))
    print(payload)


    return ''



#mca-ctrl -t connect -s "http://192.168.1.156:8080/inform" -k "9d6d6e8a16f4bb00f65f65857666c318"



def print_bytearray(value):
    print([b for b in value])

app.run(debug=True, port=8080, host='192.168.1.156')
