# coding: utf-8
from utils import UnifiTLV
from utils import mac_string_2_array, ip_string_2_array,getuptime
from struct import pack, unpack
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


    def append_last_error(self,message):
        if self.lastError is not None:
            message['last_error']=self.lastError
            self.lastError = None
    
    def run(self):
        return {
        "architecture": "mips",
        "board_rev": 33,
        "bootid": 1,
        "bootrom_version": "unifi-enlarge-buf.-1-g63fe9b5d-dirty",
        "cfgversion": "773e98c81e267e99",
        "default": False,
        "discovery_response": True,
        "dualboot": True,
        "hash_id": "d3accea4a93710a6",
        "hostname": "UBNT",
        "inform_as_notif": True,
        "inform_ip": "192.168.99.11",
        "inform_url": "http://ubuntu-utils.digiteum.com:8080/inform",
        "ip": "192.168.98.121",
        "isolated": False,
        "kernel_version": "4.4.153",
        "last_error": "Unable to resolve (http://unifi:8080/inform)",
        "locating": False,
        "mac": "78:8a:20:dc:43:89",
        "manufacturer_id": 4,
        "model": "U7LT",
        "model_display": "UAP-AC-Lite",
        "netmask": "255.255.240.0",
        "notif_payload": "",
        "notif_reason": "setparam",
        "required_version": "3.4.1",
        "selfrun_beacon": True,
        "serial": "788A20DC4389",
        "state": 0,
        "time": 1583250501,
        "time_ms": 2,
        "uptime": 66,
        "version": "4.0.80.10875"
        }
    def create_broadcast_message(self,index, version=2, command=6):
        tlv = UnifiTLV()
        tlv.add(1, bytearray(mac_string_2_array(self.mac)))
        tlv.add(2, bytearray(mac_string_2_array(self.mac) + ip_string_2_array(self.ip)))
        tlv.add(3, bytearray('{}.v{}'.format(self.device, self.firmware)))
        tlv.add(10, bytearray([ord(c) for c in pack('!I', getuptime())]))
        tlv.add(11, bytearray('UBNT'))
        tlv.add(12, bytearray(self.device))
        tlv.add(19, bytearray(mac_string_2_array(lan_mac)))
        tlv.add(18, bytearray([ord(c) for c in pack('!I', index)]))
        tlv.add(21, bytearray(self.type)) ##perhab
        tlv.add(27, bytearray(self.firmware))
        tlv.add(22, bytearray(self.firmware))
        return tlv.get(version=version, command=command)   