# coding: utf-8
from uptime import uptime
import ctypes
import struct
class TLV(object):
    def __init__(self):
        self.results = bytearray()

    def add(self, type, value):
        data = bytearray([type, ((len(value) >> 8) & 0xFF), (len(value) & 0xFF)])
        data.extend(value)
        self.results.extend(data)

    def get(self, **kwargs):
        return self.results


class UnifiTLV(TLV):

    def get(self, version, command):
        value = bytearray([version, command, 0, len(self.results)])
        value.extend(self.results)

        return value

def getuptime():

    tmp = uptime()
    if tmp is None:
        libc = ctypes.CDLL('libc.so.6')
        buf = ctypes.create_string_buffer(4096) # generous buffer to hold
                                                # struct sysinfo
        if libc.sysinfo(buf) != 0:
            print('failed')
            return -1

        tmp = struct.unpack_from('@l', buf.raw)[0]
    return 0 if tmp is None else tmp

def mac_string_2_array(mac):
    return [int(i, 16) for i in mac.split(':')]


def ip_string_2_array(mac):
    return [int(i) for i in mac.split('.')]