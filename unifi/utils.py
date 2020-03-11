# coding: utf-8
from uptime import uptime
import time
import re
import psutil
import ctypes
import struct
import os
from pfsense_utils import get_single_sysctl

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
    if tmp is None and psutil.FREEBSD :
        boottime = "0"
        matches = ""
        boottime = get_single_sysctl("kern.boottime")
        matches = re.search("sec = (\d+)", boottime)
        if matches :
	        boottime = matches.group(1)
        if int(boottime) == 0 :
            return 0
        tmp = time.time() - int(boottime)
    return 0 if tmp is None else int(tmp)



def mac_string_2_array(mac):
    return [int(i, 16) for i in mac.replace('-',':').split(':')]


def ip_string_2_array(mac):
    return [int(i) for i in mac.split('.')]

def ping(host,iface):
    """
    Returns True if host responds to a ping request
    """
    import subprocess, platform

    # Ping parameters as function of OS
    ping_str = "-n 1 " if  platform.system().lower()=="windows" else ("-c 1 " + (" -I {}".format(iface) if iface is not None else ""))
    args = "ping " + " " + ping_str + " " + host
    need_sh = False if  platform.system().lower()=="windows" else True

    # Ping
    return subprocess.call(args, shell=need_sh) == 0

def get_ipv4addr(if_addrs,lan_if):
    if if_addrs.has_key(lan_if):
        addr = if_addrs[lan_if]
        tmp = [mac for mac in addr if mac.family == 2]
        if(len(tmp)>0):
            return tmp[0]
    return None
def get_macaddr(if_addrs,lan_if):
    if if_addrs.has_key(lan_if):
        addr = if_addrs[lan_if]
        tmp = [mac for mac in addr if mac.family == -1 or mac.family==18]
        if(len(tmp)>0):
            return tmp[0]
    return None
def get_apv6addr(if_addrs,lan_if):
    if if_addrs.has_key(lan_if):
        addr = if_addrs[lan_if]
        tmp = [mac for mac in addr if mac.family == 23]
        if(len(tmp)>0):
            return tmp[0]
    return None

def _byteify(data, ignore_dicts = False):
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [ _byteify(item, ignore_dicts=True) for item in data ]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.iteritems()
        }
    # if it's anything else, return it in its original form
    return data
