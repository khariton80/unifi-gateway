# coding: utf-8
import logging
from utils import UnifiTLV
from utils import mac_string_2_array, ip_string_2_array,getuptime
from struct import pack, unpack
import socket
import binascii
import time
import psutil

import basecommand
DS_UNKNOWN=1
DS_ADOPTING=0
DS_READY=2
class BaseDevice:
    def __init__(self,mac="",ip="",firmware="",device="",type=""):
        self.lastError = None
        self.mac = mac
        self.ip = ip
        self.firmware = firmware
        self.device = device
        self.type = type
        self.state=DS_UNKNOWN
        self.broadcast_index = 0


    def append_last_error(self,message):
        if self.lastError is not None:
            message['last_error']=self.lastError
            self.lastError = None
    
    def sendinfo(self):
        logging.debug("sendinfo")
        logging.debug(self.get_system_stats())
        self.send_broadcast()

    def send_broadcast(self):
        logging.debug('Send broadcast message #{} from gateway {}'.format(self.broadcast_index, self.ip))
        self.broadcast_index+=1
        addrinfo = socket.getaddrinfo('233.89.188.1', None)[0]
        sock = socket.socket(addrinfo[0], socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 20,)
        sock.bind(('0.0.0.0', 0))
        message = self.create_broadcast_message(self.broadcast_index)
        logging.debug('Message "{}"'.format(binascii.hexlify(message)))
        sock.sendto(message, (addrinfo[4][0], 10001))
        logging.debug('Send broadcast message #{} from gateway {}'.format(self.broadcast_index, self.ip))
        
    


    def cfgversion(self):
        return "" 
    def version(self):
        return ""     
    def createNotify(self):
        return {
        "architecture": "mips",
        "board_rev": 33,
        "bootid": 1,
        "bootrom_version": "unifi-enlarge-buf.-1-g63fe9b5d-dirty",
        "cfgversion": self.cfgversion(),
        "default": False,
        "discovery_response": True,
        "dualboot": True,
        "hash_id": "d3accea4a93710a6",
        "hostname": "UBNT",
        "inform_as_notif": True,
        "inform_ip": "192.168.99.11",
        "inform_url": "http://ubuntu-utils.digiteum.com:8080/inform",
        "ip": self.ip,
        "isolated": False,
        "kernel_version": "4.4.153",
        "last_error": "Unable to resolve (http://unifi:8080/inform)",
        "locating": False,
        "mac": self.mac,
        "manufacturer_id": 4,
        "model": self.device,
        "model_display": self.type,
        "netmask": "255.255.240.0",
        "notif_payload": "",
        "notif_reason": "setparam",
        "required_version": "3.4.1",
        "selfrun_beacon": True,
        "serial": self.mac.replace(':', ''),
        "state": self.state,
        "time": int(time.time()),
        "time_ms": 2,
        "uptime": getuptime(),
        "version": self.firmware
        }
    def create_broadcast_message(self, version=2, command=6):
        tlv = UnifiTLV()
        tlv.add(1, bytearray(mac_string_2_array(self.mac)))
        tlv.add(2, bytearray(mac_string_2_array(self.mac) + ip_string_2_array(self.ip)))
        tlv.add(3, bytearray('{}.v{}'.format(self.device, self.firmware)))
        tlv.add(10, bytearray([ord(c) for c in pack('!I', getuptime())]))
        tlv.add(11, bytearray('UBNT'))
        tlv.add(12, bytearray(self.device))
        tlv.add(19, bytearray(mac_string_2_array(self.mac)))
        tlv.add(18, bytearray([ord(c) for c in pack('!I', self.broadcast_index)]))
        tlv.add(21, bytearray(self.device)) 
        tlv.add(27, bytearray(self.firmware))
        tlv.add(22, bytearray(self.firmware))
        return tlv.get(version=version, command=command)   

    def get_sys_stats(self):
        loadavg = psutil.getloadavg()
        mem = psutil.virtual_memory()
        return {
            "loadavg_1":  loadavg[0],
            "loadavg_15": loadavg[1],
            "loadavg_5":  loadavg[2],
            "mem_buffer": 0,
            "mem_total": mem.total,
            "mem_used": mem.used
        } 
    def get_system_stats(self):
        mem = psutil.virtual_memory()
        return {
                 "cpu": psutil.cpu_percent(),
                 "mem": mem.percent,
                 "uptime": getuptime()
            }  