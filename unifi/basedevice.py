# coding: utf-8
import logging
from utils import UnifiTLV
from utils import mac_string_2_array, ip_string_2_array,getuptime
from struct import pack, unpack
import socket
import binascii
import time
import psutil
import cryptoutils
import urllib2
import json
import basecommand

import basecommand
DS_UNKNOWN=1
DS_ADOPTING=0
DS_READY=2
class BaseDevice:
    def __init__(self,mac="",ip="",firmware="",device="",type=""):
        self.lastError = "None"
        self.mac = mac
        self.ip = ip
        self.firmware = firmware
        self.device = device
        self.type = type
        self.state=DS_READY
        self.broadcast_index = 0
        self.delayStart = int(round(time.time()  * 1000)) 
        self.interval = 10 * 1000
        self.nextCommand =None

    def getCurrentMessageType(self):
        return -1 
    def append_last_error(self,message):
        if self.lastError is not None:
            message['last_error']=self.lastError
            self.lastError = None
    
    def sendinfo(self):
        logging.debug("sendinfo")
        if self.nextCommand is not None:
            if self.nextCommand.type == basecommand.CMD_DISCOVER :
                self.send_discover()
            if self.nextCommand.type == basecommand.CMD_NOTIFY :
                self.parseResponse(self._send_inform(self.nextCommand.data,False))
            if self.nextCommand.type == basecommand.CMD_INFORM :
                self.parseResponse(self._send_inform(self.nextCommand.data,False))

            self.nextCommand = None
        else:
            currentMessage = self.getCurrentMessageType()
            if currentMessage == -1: #brodcast
                self.send_broadcast()
            elif currentMessage == 0: #notify 
                self.send_notify()   
            elif currentMessage == 1: #discover 
                self.send_discover()
            else:       
                self.send_inform()   
    def _send_inform(self, data,usecbc):
        data = json.dumps(data)
        headers = {
            'Content-Type': 'application/x-binary',
            'User-Agent': 'AirControl Agent v1.0'
        }
        url = self.getInformUrl()

        logging.debug('Send inform request to {} : {}'.format(url, data))
        request = urllib2.Request(url, cryptoutils.encode_inform(self.getKey(),data,usecbc,self.mac), headers)
        response = urllib2.urlopen(request)
        result = cryptoutils.decode_inform(self.getKey(), response.read())
        logging.debug(result)
        return result

    def send_broadcast(self):
        logging.debug('Send broadcast message #{} from gateway {}'.format(self.broadcast_index, self.ip))
        self.broadcast_index+=1
        if self.broadcast_index>20 :
            self.broadcast_index = 0
        addrinfo = socket.getaddrinfo('233.89.188.1', None)[0]   #233.89.188.1  wireshark show normal broadcast
        sock = socket.socket(addrinfo[0], socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 20,)
        sock.bind((self.ip, 0))
        message = self.create_broadcast_message(self.broadcast_index)
        logging.debug('Message "{}"'.format(binascii.hexlify(message)))
        sock.sendto(message, (addrinfo[4][0], 10001))
        logging.debug('Send broadcast message #{} from gateway {}'.format(self.broadcast_index, self.ip))
        
    
    def send_discover(self):
        base = self.createBaseInform()
        base['discovery_response']= True
        self.parseResponse(self._send_inform(base,True))
    def send_inform(self):
        base = self.createBaseInform()
        base['discovery_response']= False
        base['state']= DS_READY
        self.parseResponse(self._send_inform(base,False))
    def send_notify(self,wasAdopted):
        self.parseResponse(self._send_inform(self.createNotify(wasAdopted),True))
    def parseResponse(self,data):
        pass

    def cfgversion(self):
        return "" 
    def getKey(self):
        return ""
    def version(self):
        return ""
    def getInformUrl(self):
        return "http://ubuntu-utils.digiteum.com:8080/inform"
    def getInformIp(self):
        return "192.168.99.11"                      
    def getHostname(self):
        return "UBNT"                      
    def createBaseInform1(self):
        ctime = time.time()
        msg = {
        "fingerprint": "b2:5b:e2:98:c3:b1:2e:2e:38:fd:f9:34:b7:72:9e:67",    
        "architecture": "mips",
        "board_rev": 33,
        "bootid": 1,
        "bootrom_version": "unifi-enlarge-buf.-1-g63fe9b5d-dirty",
        "cfgversion": self.cfgversion(),
        "default": False,
        "dualboot": True,
        "hash_id": "d3accea4a93710a6",
        "hostname": self.getHostname(),
        "inform_ip": self.getInformIp(),
        "inform_url": self.getInformUrl(),
        "ip": self.ip,
        "isolated": False,
        "kernel_version": "4.4.153",
        "locating": False,
        "mac": self.mac,
        "manufacturer_id": 4,
        "model": self.device,
        "model_display": self.type,
        "netmask": "255.255.240.0",
        "required_version": "3.4.1",
        "selfrun_beacon": True,
        "serial": self.mac.replace(':', ''),
        "state": self.state,
        "time": int(ctime),
        "time_ms": int((ctime-int(ctime))*1000),
        "uptime": getuptime(),
        "version": self.firmware
        }

        if self.lastError is not None:
            msg['last_error']=self.lastError
            self.lastError = None

        return msg

    def createBaseInform(self):
        ctime = time.time()
        msg = {
  "bootrom_version": "unknown",
  "cfgversion": self.cfgversion(),
  "config_network_wan": {
    "type": "dhcp"
  },
  "config_network_wan2": {
    "dns1": "10.1.1.1",
    "gateway": "10.1.1.1",
    "ip": "10.1.1.10",
    "netmask": "255.255.255.0",
    "type": "static"
  },
  "config_port_table": [
    {
      "ifname": "eth0",
      "name": "wan"
    },
    {
      "ifname": "eth1",
      "name": "lan"
    },
    {
      "ifname": "eth2",
      "name": "wan2"
    }
  ],
  "connect_request_ip": self.ip,
  "connect_request_port": "36424",
  "ddns-status": {
    "dyndns": [
      {
        "atime": 0,
        "host_name": "hostname",
        "ip": "20.1.2.3",
        "mtime": 1412958,
        "status": "good",
        "warned_min_error_interval": 0,
        "warned_min_interval": 0,
        "wtime": 30
      }
    ]
  },
  "default": False,
  "discovery_response": False,
  "dpi-clients": [
    "80:2a:a8:f0:ef:78"
  ],
  "dpi-stats": [
    {
      "initialized": "94107792805",
      "mac": "80:2a:a8:f0:ef:78",
      "stats": [
        {
          "app": 5,
          "cat": 3,
          "rx_bytes": 82297468,
          "rx_packets": 57565,
          "tx_bytes": 1710174,
          "tx_packets": 25324
        },
        {
          "app": 94,
          "cat": 19,
          "rx_bytes": 1593846895,
          "rx_packets": 1738901,
          "tx_bytes": 348738675,
          "tx_packets": 2004045
        },
        {
          "app": 133,
          "cat": 3,
          "rx_bytes": 531190,
          "rx_packets": 2465,
          "tx_bytes": 676859,
          "tx_packets": 2760
        },
        {
          "app": 222,
          "cat": 13,
          "rx_bytes": 3441437,
          "rx_packets": 3033,
          "tx_bytes": 203173,
          "tx_packets": 1468
        },
        {
          "app": 23,
          "cat": 0,
          "rx_bytes": 0,
          "rx_packets": 0,
          "tx_bytes": 145,
          "tx_packets": 2
        },
        {
          "app": 7,
          "cat": 0,
          "rx_bytes": 0,
          "rx_packets": 0,
          "tx_bytes": 145,
          "tx_packets": 2
        },
        {
          "app": 7,
          "cat": 13,
          "rx_bytes": 24417806554,
          "rx_packets": 18415873,
          "tx_bytes": 2817966897,
          "tx_packets": 9910192
        },
        {
          "app": 185,
          "cat": 20,
          "rx_bytes": 28812050,
          "rx_packets": 208945,
          "tx_bytes": 160819147,
          "tx_packets": 1228992
        },
        {
          "app": 65535,
          "cat": 255,
          "rx_bytes": 182029551,
          "rx_packets": 1796815,
          "tx_bytes": 435732626,
          "tx_packets": 1933469
        },
        {
          "app": 4,
          "cat": 10,
          "rx_bytes": 1522,
          "rx_packets": 20,
          "tx_bytes": 882,
          "tx_packets": 12
        },
        {
          "app": 106,
          "cat": 18,
          "rx_bytes": 982710,
          "rx_packets": 10919,
          "tx_bytes": 1010970,
          "tx_packets": 11233
        },
        {
          "app": 30,
          "cat": 18,
          "rx_bytes": 7819852,
          "rx_packets": 20378,
          "tx_bytes": 1293104,
          "tx_packets": 18686
        },
        {
          "app": 1,
          "cat": 0,
          "rx_bytes": 0,
          "rx_packets": 0,
          "tx_bytes": 145,
          "tx_packets": 2
        },
        {
          "app": 63,
          "cat": 18,
          "rx_bytes": 780358,
          "rx_packets": 3520,
          "tx_bytes": 545757,
          "tx_packets": 6545
        },
        {
          "app": 8,
          "cat": 13,
          "rx_bytes": 180691586,
          "rx_packets": 132204,
          "tx_bytes": 5970383,
          "tx_packets": 74482
        },
        {
          "app": 21,
          "cat": 10,
          "rx_bytes": 5521547718,
          "rx_packets": 73080390,
          "tx_bytes": 179999309100,
          "tx_packets": 130627577
        }
      ]
    }
  ],
  "dpi-stats-table": [
    {
      "_id": "5875d9f9e4b02fd3851c55e4",
      "_subid": "5875d9f5e4b02fd3851c55d8",
      "by_app": [
        {
          "app": 5,
          "cat": 3,
          "rx_bytes": 2652,
          "rx_packets": 4,
          "tx_bytes": 1797,
          "tx_packets": 7
        },
        {
          "app": 94,
          "cat": 19,
          "rx_bytes": 9010458,
          "rx_packets": 6977,
          "tx_bytes": 518163,
          "tx_packets": 3533
        },
        {
          "app": 209,
          "cat": 13,
          "rx_bytes": 39303,
          "rx_packets": 90,
          "tx_bytes": 17744,
          "tx_packets": 78
        },
        {
          "app": 10,
          "cat": 4,
          "rx_bytes": 15273,
          "rx_packets": 15,
          "tx_bytes": 2728,
          "tx_packets": 23
        },
        {
          "app": 7,
          "cat": 13,
          "rx_bytes": 369394,
          "rx_packets": 293,
          "tx_bytes": 24904,
          "tx_packets": 244
        },
        {
          "app": 185,
          "cat": 20,
          "rx_bytes": 62070,
          "rx_packets": 130,
          "tx_bytes": 27219,
          "tx_packets": 169
        },
        {
          "app": 65535,
          "cat": 255,
          "rx_bytes": 976848,
          "rx_packets": 1027,
          "tx_bytes": 77317,
          "tx_packets": 695
        },
        {
          "app": 12,
          "cat": 13,
          "rx_bytes": 92924774,
          "rx_packets": 70496,
          "tx_bytes": 17360339,
          "tx_packets": 69509
        },
        {
          "app": 150,
          "cat": 3,
          "rx_bytes": 54609,
          "rx_packets": 71,
          "tx_bytes": 19749,
          "tx_packets": 85
        },
        {
          "app": 95,
          "cat": 5,
          "rx_bytes": 9835,
          "rx_packets": 41,
          "tx_bytes": 3956,
          "tx_packets": 41
        },
        {
          "app": 168,
          "cat": 20,
          "rx_bytes": 100049,
          "rx_packets": 198,
          "tx_bytes": 60396,
          "tx_packets": 275
        },
        {
          "app": 3,
          "cat": 10,
          "rx_bytes": 12538,
          "rx_packets": 36,
          "tx_bytes": 10607,
          "tx_packets": 75
        },
        {
          "app": 84,
          "cat": 3,
          "rx_bytes": 45115,
          "rx_packets": 135,
          "tx_bytes": 91866,
          "tx_packets": 158
        },
        {
          "app": 84,
          "cat": 13,
          "rx_bytes": 42563,
          "rx_packets": 102,
          "tx_bytes": 32676,
          "tx_packets": 113
        },
        {
          "app": 186,
          "cat": 20,
          "rx_bytes": 44618,
          "rx_packets": 68,
          "tx_bytes": 8826,
          "tx_packets": 86
        }
      ],
      "by_cat": [
        {
          "apps": [
            5,
            150,
            84
          ],
          "cat": 3,
          "rx_bytes": 102376,
          "rx_packets": 210,
          "tx_bytes": 113412,
          "tx_packets": 250
        },
        {
          "apps": [
            10
          ],
          "cat": 4,
          "rx_bytes": 15273,
          "rx_packets": 15,
          "tx_bytes": 2728,
          "tx_packets": 23
        },
        {
          "apps": [
            95
          ],
          "cat": 5,
          "rx_bytes": 9835,
          "rx_packets": 41,
          "tx_bytes": 3956,
          "tx_packets": 41
        },
        {
          "apps": [
            3
          ],
          "cat": 10,
          "rx_bytes": 12538,
          "rx_packets": 36,
          "tx_bytes": 10607,
          "tx_packets": 75
        },
        {
          "apps": [
            209,
            7,
            12,
            84
          ],
          "cat": 13,
          "rx_bytes": 93376034,
          "rx_packets": 70981,
          "tx_bytes": 17435663,
          "tx_packets": 69944
        },
        {
          "apps": [
            94
          ],
          "cat": 19,
          "rx_bytes": 9010458,
          "rx_packets": 6977,
          "tx_bytes": 518163,
          "tx_packets": 3533
        },
        {
          "apps": [
            185,
            168,
            186
          ],
          "cat": 20,
          "rx_bytes": 206737,
          "rx_packets": 396,
          "tx_bytes": 96441,
          "tx_packets": 530
        },
        {
          "apps": [
            65535
          ],
          "cat": 255,
          "rx_bytes": 976848,
          "rx_packets": 1027,
          "tx_bytes": 77317,
          "tx_packets": 695
        }
      ],
      "initialized": "88122111307"
    },
    {
      "_id": "5875d9f9e4b02fd3851c55e4",
      "_subid": "5875e1f8e4b0ba28be0f8335",
      "by_app": [
        {
          "app": 5,
          "cat": 3,
          "clients": [
            {
              "mac": "80:2a:a8:f0:ef:78",
              "rx_bytes": 82297468,
              "rx_packets": 57565,
              "tx_bytes": 1710174,
              "tx_packets": 25324
            }
          ],
          "known_clients": 1,
          "rx_bytes": 82300120,
          "rx_packets": 57569,
          "tx_bytes": 1711971,
          "tx_packets": 25331
        },
        {
          "app": 94,
          "cat": 19,
          "clients": [
            {
              "mac": "80:2a:a8:f0:ef:78",
              "rx_bytes": 1593846895,
              "rx_packets": 1738901,
              "tx_bytes": 348738675,
              "tx_packets": 2004045
            }
          ],
          "known_clients": 1,
          "rx_bytes": 1622602418,
          "rx_packets": 1760201,
          "tx_bytes": 349693010,
          "tx_packets": 2012708
        },
        {
          "app": 209,
          "cat": 13,
          "rx_bytes": 43670,
          "rx_packets": 100,
          "tx_bytes": 20728,
          "tx_packets": 91
        },
        {
          "app": 10,
          "cat": 4,
          "rx_bytes": 15273,
          "rx_packets": 15,
          "tx_bytes": 2728,
          "tx_packets": 23
        },
        {
          "app": 133,
          "cat": 3,
          "clients": [
            {
              "mac": "80:2a:a8:f0:ef:78",
              "rx_bytes": 531190,
              "rx_packets": 2465,
              "tx_bytes": 676859,
              "tx_packets": 2760
            }
          ],
          "known_clients": 1,
          "rx_bytes": 531190,
          "rx_packets": 2465,
          "tx_bytes": 676859,
          "tx_packets": 2760
        },
        {
          "app": 222,
          "cat": 13,
          "clients": [
            {
              "mac": "80:2a:a8:f0:ef:78",
              "rx_bytes": 3441437,
              "rx_packets": 3033,
              "tx_bytes": 203173,
              "tx_packets": 1468
            }
          ],
          "known_clients": 1,
          "rx_bytes": 3441437,
          "rx_packets": 3033,
          "tx_bytes": 203173,
          "tx_packets": 1468
        },
        {
          "app": 23,
          "cat": 0,
          "clients": [
            {
              "mac": "80:2a:a8:f0:ef:78",
              "rx_bytes": 0,
              "rx_packets": 0,
              "tx_bytes": 145,
              "tx_packets": 2
            }
          ],
          "known_clients": 1,
          "rx_bytes": 0,
          "rx_packets": 0,
          "tx_bytes": 145,
          "tx_packets": 2
        },
        {
          "app": 7,
          "cat": 0,
          "clients": [
            {
              "mac": "80:2a:a8:f0:ef:78",
              "rx_bytes": 0,
              "rx_packets": 0,
              "tx_bytes": 145,
              "tx_packets": 2
            }
          ],
          "known_clients": 1,
          "rx_bytes": 0,
          "rx_packets": 0,
          "tx_bytes": 145,
          "tx_packets": 2
        },
        {
          "app": 7,
          "cat": 13,
          "clients": [
            {
              "mac": "80:2a:a8:f0:ef:78",
              "rx_bytes": 24417806554,
              "rx_packets": 18415873,
              "tx_bytes": 2817966897,
              "tx_packets": 9910192
            }
          ],
          "known_clients": 1,
          "rx_bytes": 24418175948,
          "rx_packets": 18416166,
          "tx_bytes": 2817991801,
          "tx_packets": 9910436
        },
        {
          "app": 185,
          "cat": 20,
          "clients": [
            {
              "mac": "80:2a:a8:f0:ef:78",
              "rx_bytes": 28812050,
              "rx_packets": 208945,
              "tx_bytes": 160819147,
              "tx_packets": 1228992
            }
          ],
          "known_clients": 1,
          "rx_bytes": 28874120,
          "rx_packets": 209075,
          "tx_bytes": 160846366,
          "tx_packets": 1229161
        },
        {
          "app": 65535,
          "cat": 255,
          "clients": [
            {
              "mac": "80:2a:a8:f0:ef:78",
              "rx_bytes": 182029551,
              "rx_packets": 1796815,
              "tx_bytes": 435732626,
              "tx_packets": 1933469
            }
          ],
          "known_clients": 1,
          "rx_bytes": 183022079,
          "rx_packets": 1798016,
          "tx_bytes": 435832672,
          "tx_packets": 1934359
        },
        {
          "app": 12,
          "cat": 13,
          "rx_bytes": 92925290,
          "rx_packets": 70498,
          "tx_bytes": 17360839,
          "tx_packets": 69512
        },
        {
          "app": 4,
          "cat": 10,
          "clients": [
            {
              "mac": "80:2a:a8:f0:ef:78",
              "rx_bytes": 1522,
              "rx_packets": 20,
              "tx_bytes": 882,
              "tx_packets": 12
            }
          ],
          "known_clients": 1,
          "rx_bytes": 1522,
          "rx_packets": 20,
          "tx_bytes": 882,
          "tx_packets": 12
        },
        {
          "app": 106,
          "cat": 18,
          "clients": [
            {
              "mac": "80:2a:a8:f0:ef:78",
              "rx_bytes": 982710,
              "rx_packets": 10919,
              "tx_bytes": 1010970,
              "tx_packets": 11233
            }
          ],
          "known_clients": 1,
          "rx_bytes": 982710,
          "rx_packets": 10919,
          "tx_bytes": 1010970,
          "tx_packets": 11233
        },
        {
          "app": 30,
          "cat": 18,
          "clients": [
            {
              "mac": "80:2a:a8:f0:ef:78",
              "rx_bytes": 7819852,
              "rx_packets": 20378,
              "tx_bytes": 1293104,
              "tx_packets": 18686
            }
          ],
          "known_clients": 1,
          "rx_bytes": 7819852,
          "rx_packets": 20378,
          "tx_bytes": 1293104,
          "tx_packets": 18686
        },
        {
          "app": 1,
          "cat": 0,
          "clients": [
            {
              "mac": "80:2a:a8:f0:ef:78",
              "rx_bytes": 0,
              "rx_packets": 0,
              "tx_bytes": 145,
              "tx_packets": 2
            }
          ],
          "known_clients": 1,
          "rx_bytes": 0,
          "rx_packets": 0,
          "tx_bytes": 145,
          "tx_packets": 2
        },
        {
          "app": 150,
          "cat": 3,
          "rx_bytes": 54609,
          "rx_packets": 71,
          "tx_bytes": 19749,
          "tx_packets": 85
        },
        {
          "app": 95,
          "cat": 5,
          "rx_bytes": 9835,
          "rx_packets": 41,
          "tx_bytes": 3956,
          "tx_packets": 41
        },
        {
          "app": 168,
          "cat": 20,
          "rx_bytes": 100583,
          "rx_packets": 204,
          "tx_bytes": 62503,
          "tx_packets": 296
        },
        {
          "app": 3,
          "cat": 10,
          "rx_bytes": 12916,
          "rx_packets": 41,
          "tx_bytes": 11501,
          "tx_packets": 86
        },
        {
          "app": 84,
          "cat": 13,
          "rx_bytes": 42563,
          "rx_packets": 102,
          "tx_bytes": 32676,
          "tx_packets": 113
        },
        {
          "app": 84,
          "cat": 3,
          "rx_bytes": 62456,
          "rx_packets": 166,
          "tx_bytes": 101105,
          "tx_packets": 183
        },
        {
          "app": 63,
          "cat": 18,
          "clients": [
            {
              "mac": "80:2a:a8:f0:ef:78",
              "rx_bytes": 780358,
              "rx_packets": 3520,
              "tx_bytes": 545757,
              "tx_packets": 6545
            }
          ],
          "known_clients": 1,
          "rx_bytes": 780358,
          "rx_packets": 3520,
          "tx_bytes": 545757,
          "tx_packets": 6545
        },
        {
          "app": 8,
          "cat": 13,
          "clients": [
            {
              "mac": "80:2a:a8:f0:ef:78",
              "rx_bytes": 180691586,
              "rx_packets": 132204,
              "tx_bytes": 5970383,
              "tx_packets": 74482
            }
          ],
          "known_clients": 1,
          "rx_bytes": 180691586,
          "rx_packets": 132204,
          "tx_bytes": 5970383,
          "tx_packets": 74482
        },
        {
          "app": 186,
          "cat": 20,
          "rx_bytes": 44618,
          "rx_packets": 68,
          "tx_bytes": 8826,
          "tx_packets": 86
        },
        {
          "app": 21,
          "cat": 10,
          "clients": [
            {
              "mac": "80:2a:a8:f0:ef:78",
              "rx_bytes": 5521547718,
              "rx_packets": 73080390,
              "tx_bytes": 179999309100,
              "tx_packets": 130627577
            }
          ],
          "known_clients": 1,
          "rx_bytes": 5521547718,
          "rx_packets": 73080390,
          "tx_bytes": 179999309100,
          "tx_packets": 130627577
        }
      ],
      "by_cat": [
        {
          "apps": [
            23,
            7,
            1
          ],
          "cat": 0,
          "rx_bytes": 0,
          "rx_packets": 0,
          "tx_bytes": 435,
          "tx_packets": 6
        },
        {
          "apps": [
            5,
            133,
            150,
            84
          ],
          "cat": 3,
          "rx_bytes": 82948375,
          "rx_packets": 60271,
          "tx_bytes": 2509684,
          "tx_packets": 28359
        },
        {
          "apps": [
            10
          ],
          "cat": 4,
          "rx_bytes": 15273,
          "rx_packets": 15,
          "tx_bytes": 2728,
          "tx_packets": 23
        },
        {
          "apps": [
            95
          ],
          "cat": 5,
          "rx_bytes": 9835,
          "rx_packets": 41,
          "tx_bytes": 3956,
          "tx_packets": 41
        },
        {
          "apps": [
            4,
            3,
            21
          ],
          "cat": 10,
          "rx_bytes": 5521562156,
          "rx_packets": 73080451,
          "tx_bytes": 179999321483,
          "tx_packets": 130627675
        },
        {
          "apps": [
            209,
            222,
            7,
            12,
            84,
            8
          ],
          "cat": 13,
          "rx_bytes": 24695320494,
          "rx_packets": 18622103,
          "tx_bytes": 2841579600,
          "tx_packets": 10056102
        },
        {
          "apps": [
            106,
            30,
            63
          ],
          "cat": 18,
          "rx_bytes": 9582920,
          "rx_packets": 34817,
          "tx_bytes": 2849831,
          "tx_packets": 36464
        },
        {
          "apps": [
            94
          ],
          "cat": 19,
          "rx_bytes": 1622602418,
          "rx_packets": 1760201,
          "tx_bytes": 349693010,
          "tx_packets": 2012708
        },
        {
          "apps": [
            185,
            168,
            186
          ],
          "cat": 20,
          "rx_bytes": 29019321,
          "rx_packets": 209347,
          "tx_bytes": 160917695,
          "tx_packets": 1229543
        },
        {
          "apps": [
            65535
          ],
          "cat": 255,
          "rx_bytes": 183022079,
          "rx_packets": 1798016,
          "tx_bytes": 435832672,
          "tx_packets": 1934359
        }
      ],
      "initialized": "88121276686",
      "is_ugw": True
    }
  ],
  "fw_caps": 3,
  "guest_token": "4C1D46707239C6EB5A2366F505A44A91",
  "has_default_route_distance": True,
  "has_dnsmasq_hostfile_update": True,
  "has_dpi": True,
  "has_eth1": True,
  "has_porta": True,
  "has_ssh_disable": True,
  "has_vti": True,
  "hostname": "usg",
  "if_table": [
    {
      "drops": 333,
      "enable": True,
      "full_duplex": True,
      "gateways": [
        "20.1.2.3"
      ],
      "ip": "20.1.2.40",
      "latency": 11,
      "mac": "80:2a:a8:cd:a9:52",
      "name": "eth0",
      "nameservers": [
        "20.1.2.19",
        "20.1.3.19"
      ],
      "netmask": "255.255.248.0",
      "num_port": 1,
      "rx_bytes": 353519562926,
      "rx_dropped": 19137,
      "rx_errors": 0,
      "rx_multicast": 65629,
      "rx_packets": 645343103,
      "speed": 1000,
      "speedtest_lastrun": 1504930035,
      "speedtest_ping": 68,
      "speedtest_status": "Idle",
      "tx_bytes": 953646055362,
      "tx_dropped": 0,
      "tx_errors": 0,
      "tx_packets": 863173990,
      "up": True,
      "uptime": 37193,
      "xput_down": 38.161000000000001,
      "xput_up": 12.484999999999999
    },
    {
      "enable": True,
      "full_duplex": True,
      "ip": "192.168.1.1",
      "mac": "80:2a:a8:cd:a9:53",
      "name": "eth1",
      "netmask": "255.255.255.0",
      "num_port": 1,
      "rx_bytes": 807912794876,
      "rx_dropped": 2800,
      "rx_errors": 0,
      "rx_multicast": 412314,
      "rx_packets": 700376545,
      "speed": 1000,
      "tx_bytes": 58901673253,
      "tx_dropped": 0,
      "tx_errors": 0,
      "tx_packets": 347161831,
      "up": True
    },
    {
      "enable": True,
      "full_duplex": True,
      "gateways": [
        "20.1.2.1"
      ],
      "ip": "10.1.1.10",
      "mac": "80:2a:a8:cd:a9:54",
      "name": "eth2",
      "nameservers": [
        "20.1.2.19",
        "20.1.3.19"
      ],
      "netmask": "255.255.255.0",
      "num_port": 1,
      "rx_bytes": 118162997,
      "rx_dropped": 1,
      "rx_errors": 0,
      "rx_multicast": 65629,
      "rx_packets": 1126891,
      "speed": 1000,
      "tx_bytes": 77684158,
      "tx_dropped": 0,
      "tx_errors": 0,
      "tx_packets": 1025525,
      "up": True
    }
  ],
  "inform_url": self.getInformUrl(),
  "ip": self.ip,
  "isolated": False,
  "locating": False,
  "mac": self.mac,
  "model": "UGW3",
  "model_display": "UniFi-Gateway-3",
  "netmask": "255.255.240.0",
  "network_table": [
    {
      "address": "10.1.1.10/24",
      "addresses": [
        "10.1.1.10/24"
      ],
      "autoneg": True,
      "duplex": "full",
      "gateways": [
        "20.1.2.1"
      ],
      "l1up": True,
      "mac": "80:2a:a8:cd:a9:54",
      "mtu": "1500",
      "name": "eth2",
      "nameservers": [
        "20.1.2.191",
        "20.1.3.191"
      ],
      "speed": "1000",
      "stats": {
        "multicast": "65627",
        "rx_bps": "0",
        "rx_bytes": 118162997,
        "rx_dropped": 1,
        "rx_errors": 0,
        "rx_multicast": 65629,
        "rx_packets": 1126891,
        "tx_bps": "0",
        "tx_bytes": 77684158,
        "tx_dropped": 0,
        "tx_errors": 0,
        "tx_packets": 1025525
      },
      "up": True
    },
    {
      "address": "192.168.1.1/24",
      "addresses": [
        "192.168.1.1/24"
      ],
      "autoneg": True,
      "duplex": "full",
      "host_table": [
        {
          "age": 0,
          "authorized": True,
          "bc_bytes": 4814073447,
          "bc_packets": 104642338,
          "dev_cat": 1,
          "dev_family": 4,
          "dev_id": 239,
          "dev_vendor": 47,
          "ip": "192.168.1.8",
          "mac": "80:2a:a8:f0:ef:78",
          "mc_bytes": 4814073447,
          "mc_packets": 104642338,
          "os_class": 15,
          "os_name": 19,
          "rx_bytes": 802239963372,
          "rx_packets": 805925675,
          "tx_bytes": 35371476651,
          "tx_packets": 104136843,
          "uptime": 5822032
        },
        {
          "age": 41,
          "authorized": True,
          "bc_bytes": 9202676,
          "bc_packets": 200043,
          "hostname": "switch",
          "ip": "192.168.1.10",
          "mac": "f0:9f:c2:09:2b:f2",
          "mc_bytes": 21366640,
          "mc_packets": 406211,
          "rx_bytes": 30862046,
          "rx_packets": 610310,
          "tx_bytes": 13628015,
          "tx_packets": 204110,
          "uptime": 5821979
        },
        {
          "age": 8,
          "authorized": True,
          "bc_bytes": 0,
          "bc_packets": 0,
          "mac": "f0:9f:c2:09:2b:f3",
          "mc_bytes": 21232297,
          "mc_packets": 206139,
          "rx_bytes": 21232297,
          "rx_packets": 206139,
          "tx_bytes": 0,
          "tx_packets": 0,
          "uptime": 5822017
        }
      ],
      "l1up": True,
      "mac": "80:2a:a8:cd:a9:53",
      "mtu": "1500",
      "name": "eth1",
      "speed": "1000",
      "stats": {
        "multicast": "412294",
        "rx_bps": "342",
        "rx_bytes": 52947224765,
        "rx_dropped": 2800,
        "rx_errors": 0,
        "rx_multicast": 412314,
        "rx_packets": 341232922,
        "tx_bps": "250",
        "tx_bytes": 792205417381,
        "tx_dropped": 0,
        "tx_errors": 0,
        "tx_packets": 590930778
      },
      "up": True
    },
    {
      "address": "20.1.2.10/21",
      "addresses": [
        "20.1.2.10/21"
      ],
      "autoneg": True,
      "duplex": "full",
      "gateways": [
        "20.1.1.1"
      ],
      "l1up": True,
      "mac": "80:2a:a8:cd:a9:52",
      "mtu": "1500",
      "name": "eth0",
      "nameservers": [
        "20.1.2.1",
        "20.1.2.11"
      ],
      "speed": "1000",
      "stats": {
        "multicast": "65627",
        "rx_bps": "262",
        "rx_bytes": 353519562926,
        "rx_dropped": 19137,
        "rx_errors": 0,
        "rx_multicast": 65629,
        "rx_packets": 645343103,
        "tx_bps": "328",
        "tx_bytes": 953646055362,
        "tx_dropped": 0,
        "tx_errors": 0,
        "tx_packets": 863173990
      },
      "up": True
    }
  ],
  "pfor-stats": [
    {
      "id": "596add99e4b0a76e35003e00",
      "rx_bytes": 41444574,
      "rx_packets": 305634,
      "tx_bytes": 88048319,
      "tx_packets": 364768
    }
  ],
  "radius_caps": 1,
  "required_version": "4.0.0",
  "routes": [
    {
      "nh": [
        {
          "intf": "eth0",
          "metric": "1/0",
          "t": "S>*",
          "via": "20.1.1.1"
        }
      ],
      "pfx": "0.0.0.0/0"
    },
    {
      "nh": [
        {
          "intf": "eth2",
          "metric": "220/0",
          "t": "S  ",
          "via": "10.1.1.1"
        }
      ],
      "pfx": "0.0.0.0/0"
    },
    {
      "nh": [
        {
          "intf": "eth2",
          "metric": "1/0",
          "t": "S  "
        }
      ],
      "pfx": "10.1.1.0/24"
    },
    {
      "nh": [
        {
          "intf": "eth2",
          "t": "C>*"
        }
      ],
      "pfx": "10.1.1.0/24"
    },
    {
      "nh": [
        {
          "intf": "lo",
          "t": "C>*"
        }
      ],
      "pfx": "127.0.0.0/8"
    },
    {
      "nh": [
        {
          "intf": "eth1",
          "t": "C>*"
        }
      ],
      "pfx": "192.168.1.0/24"
    },
    {
      "nh": [
        {
          "intf": "eth0",
          "t": "C>*"
        }
      ],
      "pfx": "20.1.1.0/21"
    }
  ],
  "selfrun_beacon": True,
  "serial": self.mac.replace(':', ''),
  "speedtest-status": {
    "latency": 0,
    "rundate": 0,
    "runtime": 0,
    "status_download": 0,
    "status_ping": 1,
    "status_summary": 1,
    "status_upload": 0,
    "xput_download": 0.0,
    "xput_upload": 0.0
  },
  "state": 2,
  "system-stats": {
    "cpu": "8",
    "mem": "24",
    "uptime": getuptime()
  },
  "time": int(time.time()),
  "uplink": "eth0",
  "uptime": getuptime(),
  "version": self.firmware,
  "vpn": {
    "ipsec": {
      "sa": [
        {
          "active_time": 0,
          "connect_id": "peer-1.2.3.4-tunnel-0",
          "in_bytes": "n/a",
          "lifetime": 0,
          "local_id": "n/a",
          "local_ip": "n/a",
          "nat_t": False,
          "out_bytes": "n/a",
          "peer_id": "1.2.3.4",
          "remote_id": "n/a",
          "remote_ip": "n/a",
          "state": "down"
        },
        {
          "active_time": 0,
          "connect_id": "peer-1.2.3.4-tunnel-1",
          "in_bytes": "n/a",
          "lifetime": 0,
          "local_id": "n/a",
          "local_ip": "n/a",
          "nat_t": False,
          "out_bytes": "n/a",
          "peer_id": "1.2.3.4",
          "remote_id": "n/a",
          "remote_ip": "n/a",
          "state": "down"
        }
      ]
    }
  }
}


        if self.lastError is not None:
            msg['last_error']=self.lastError
            self.lastError = None

        return msg

    def createNotify(self,wasAdopted):
        base = self.createBaseInform()
        base['inform_as_notif']=True
        base['notif_reason']='setparam'
        base['notif_payload']=''
        base['state']=DS_READY
        if not wasAdopted:
            base['discovery_response']= not wasAdopted
        return base
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