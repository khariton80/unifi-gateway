# coding: utf-8
import os.path
import ConfigParser
import logging
from utils import UnifiTLV
from utils import mac_string_2_array, ip_string_2_array,getuptime,get_ipv4addr,get_macaddr,_byteify
from pfsense_utils import pfsense_const, get_temp
from struct import pack, unpack
import socket 
import binascii
import time
import psutil
import cryptoutils
import urllib2
import json
import basecommand
import stun
import psutil

import pfsense_config
import basecommand
DS_UNKNOWN=1
DS_ADOPTING=0
DS_READY=2
class BaseDevice:
    def __init__(self,device="",type="",configfile=""):
        self.configfile=configfile
        self.mapfile=configfile.replace(".conf",".map")
        #pfsense_const['cf_conf_path']='conf'
        self.pfsenseConfig = pfsense_config.PfsenseConfig(pfsense_const['cf_conf_path']+'/config.xml')

        if (not os.path.exists(configfile)):
            self.createEmptyConfig()
        if (not os.path.exists(self.mapfile)):
            self.createEmptyMap()
        self.reload_config()
        self.reload_map()

        self.lastError = "None"
        self.firmware = self.config['gateway']['firmware']
        self.device = device
        self.type = type
        self.state=DS_READY
        self.broadcast_index = 0
        self.interval = 10 * 1000
        self.nextCommand =None
        self.delayStart = int(round(time.time()  * 1000)) - self.interval

        if(self.config.has_key('gateway') and self.config['gateway'].has_key('lan_if')):
            lan_if = self.config['gateway']['lan_if']
            if_addrs = psutil.net_if_addrs()
            macaddr = get_macaddr(if_addrs,lan_if)
            ipv4 = get_ipv4addr(if_addrs,lan_if)
            if macaddr is not None:
                self.mac=macaddr.address.replace('-',':').lower()
            if ipv4 is not None:
                self.ip=ipv4.address
                self.netmask=ipv4.netmask    

        

    def createEmptyConfig(self):
        self.config = { 
            'global':{
                'pid_file' : 'unifi-gateway.pid'
                },
                'gateway':{
                    'is_adopted':False,
                    'lan_if':self.pfsenseConfig.getDefaultLan()["if"],
                    'firmware':'4.4.44.5213871',
                    'showhosts':False
                }
        }
        self.save_config()
    def getDefaultMap(self,lan,wan):
        pass            
    def createEmptyMap(self):
        self.mapConfig = self.getDefaultMap(self.pfsenseConfig.getDefaultLan()["if"],self.pfsenseConfig.getDefaultWan()["if"])
        self.save_map()
    
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
                self._send_stun()   
    
    def _send_inform(self, data,usecbc):
        data = json.dumps(data)
        headers = {
            'Content-Type': 'application/x-binary',
            'User-Agent': 'AirControl Agent v1.0'
        }
        url = self.getInformUrl()

        logging.debug('Send inform request to {} : {}'.format(url, data))
        try:
            request = urllib2.Request(url, cryptoutils.encode_inform(self.getKey(),data,usecbc,self.mac), headers)
            response = urllib2.urlopen(request)
            result = cryptoutils.decode_inform(self.getKey(), response.read())
            return result
        except Exception as ex:
            logging.warn(ex)
            self.lastError = ex.message
            return None


    def send_broadcast(self):
        logging.debug('Send broadcast message #{} from gateway {}'.format(self.broadcast_index, self.ip))
        self.broadcast_index+=1
        if self.broadcast_index>20 :
            self.broadcast_index = 0

        addrinfo = socket.getaddrinfo('233.89.188.1', None)[0]   #233.89.188.1  wireshark show normal broadcast
        sock = socket.socket(addrinfo[0], socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
        sock.bind((self.ip, 0))
        message = self.create_broadcast_message(self.broadcast_index)
        sock.sendto(message, (addrinfo[4][0], 10001))
        logging.debug('Send broadcast message #{} from gateway {}'.format(self.broadcast_index, self.ip))
    
    def send_discover(self):
        base = self.cerateInformMessage()
        base['discovery_response']= True
        base['state']= DS_UNKNOWN
        self.parseResponse(self._send_inform(base,True))
    
    def send_inform(self):
        base = self.cerateInformMessage()
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
    
    def appendExtraBaseInfo(self,data):
      pass

    def appendExtraInformMessage(self,data):
      pass
    
    def cerateInformMessage(self):
      base = self.createBaseInform()
      base['sys_stats']=self.get_sys_stats()
      base['system-stats']=self.get_system_stats()

      self.appendExtraInformMessage(base)
      return base
    
    def createBaseInform(self):
        ctime = time.time()
        msg = {
        "fingerprint": "b2:5b:e2:98:c3:b1:2e:2e:38:fd:f9:34:b7:72:9e:67",    
        "board_rev": 33,
        "bootid": 1,
        "bootrom_version": "unifi-enlarge-buf.-1-g63fe9b5d-dirty",
        "cfgversion": self.cfgversion(),
        "default": False,
        "dualboot": True,
        "hash_id": self.mac.replace(':', ''),
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
        "netmask": self.netmask,
        "required_version": "3.4.1",
        "selfrun_beacon": True,
        "serial": self.mac.replace(':', ''),
        "state": self.state,
        "time": int(ctime),
        "time_ms": int((ctime-int(ctime))*1000),
        "uptime": getuptime(),
        "version": self.firmware,
        "connect_request_ip":self.ip,
        "connect_request_port":57201

        }


        if self.lastError is not None:
            msg['last_error']=self.lastError
            self.lastError = None
        
        self.appendExtraBaseInfo(msg)

        return msg

    def createNotify(self,reason,payload):
        base = self.createBaseInform()
        base['inform_as_notif']=True
        base['notif_reason']=reason
        base['notif_payload']=payload
        base['state']=DS_ADOPTING
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
            "loadavg_1":  loadavg[0]+0.2,
            "loadavg_15": loadavg[1]+0.3,
            "loadavg_5":  loadavg[2]+0.1,
            "mem_buffer": 0,
            "mem_total": mem.total,
            "mem_used": mem.used
        } 
    
    def _send_stun(self):
        try:
            if self.config.has_key('mgmt_cfg') and self.config['mgmt_cfg'].has_key('stun_url'):
                client = stun.StunClient()
                client.send_request(self.config['mgmt_cfg']['stun_url'])
                result = client.receive_response()
                client.close()

                for item in result: 
                    if 'MAPPED-ADDRESS' == item['name']:
                        self.config['gateway']['lan_ip']=item['ip']
                        self.config['gateway']['lan_port']=item['port']
                        self.save_config()
        except Exception as ex:
            logging.warn(ex)
            self.lastError = ex.message
            return None  
     

    def get_system_stats(self):
        mem = psutil.virtual_memory()
        return {
                 "cpu": psutil.cpu_percent(),
                 "mem": mem.percent,
                 "uptime": getuptime(),
                 "temps": {
                        "Board (CPU)": get_temp(),
                        "Board (PHY)": get_temp(),
                        "CPU": get_temp(),
                        "PHY": get_temp()
                        }
            }
    def reload_config(self):
        with open(self.configfile) as config_file:
            self.config = json.load(config_file,object_hook= _byteify)  
    def save_config(self):
        with open(self.configfile, 'w') as config_file:
            json.dump(self.config, config_file,indent=True,sort_keys=True)

    def reload_map(self):
        with open(self.mapfile) as config_file:
            self.mapConfig = json.load(config_file,object_hook= _byteify)  
    def save_map(self):
        with open(self.mapfile, 'w') as config_file:
            json.dump(self.mapConfig, config_file,indent=True,sort_keys=True)

        