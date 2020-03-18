# coding: utf-8
from basedevice import BaseDevice
import basecommand 
import json
import re
import psutil
import utils
import pfsense_utils
import ip_calculator
import time
import thread
import logging

class UnifiUSGPro(BaseDevice):
    def __init__(self,configfile):
        BaseDevice.__init__(self,'UGW4','UniFi-Gateway-3',configfile)
        self.wan_addresses=[]
                
    def cfgversion(self):
        if self.config.has_key('mgmt_cfg') and self.config['mgmt_cfg'].has_key('cfgversion'):
             return self.config['mgmt_cfg']['cfgversion']
        else:
            return "?"
    def getDefaultMap(self,lan,wan):
        return { 
            'ports':[
                {
                    'unifi':"eth0",
                    'unifi-description':"LAN",
                    'pfsense':lan,
                    'enabled':True,
                    'wan':False
                },
                {
                    'unifi':"eth1",
                    'unifi-description':"",
                    'pfsense':"",
                    'enabled':False,
                    'wan':False
                },
                {
                    'unifi':"eth2",
                    'unifi-description':"WAN",
                    'pfsense':wan,
                    'enabled':True,
                    'wan':True
                },
                {
                    'unifi':"eth3",
                    'unifi-description':"",
                    'pfsense':"",
                    'enabled':False,
                    'wan':True
                }
            ]
        }
    def getCurrentMessageType(self):
        if (self.config.has_key('gateway') 
            and not self.config['gateway']['is_adopted'] 
            and (not self.config['gateway'].has_key('key') or self.config['gateway']['key']=="" )):
            return -1     
        if (self.config.has_key('gateway') 
            and not self.config['gateway']['is_adopted'] 
            and self.config['gateway'].has_key('key') 
            and not self.config['gateway']['key']=="") : #discover
            return 1     
        if self.config.has_key('gateway') and self.config['gateway']['is_adopted'] : #info
            return 2     
    def getInformUrl(self):
        return self.config['gateway']['url']
    def getInformIp(self):
        return "127.0.0.1"                      
    def getHostname(self):
        if self.config['gateway'].has_key('host') :
            return self.config['gateway']['host']
        return "UBNT"      
    def getKey(self):
        return self.config['gateway']['key']

    def appendVPN(self,data,if_stats,io_counters,if_addrs):
        data['vpn'] = {
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

    def appendWAN(self,data,if_stats,io_counters,if_addrs):
        data["config_network_wan"]= {
                "type": "dhcp"
            }
        data["config_network_wan2"]= {
            "dns1": "10.1.1.1",
            "gateway": "10.1.1.1",
            "ip": "10.1.1.10",
            "netmask": "255.255.255.0",
            "type": "static"
        }

    def create_if_element(self,interface,if_stats,io_counters,if_addrs,dpingerStatuses,hostsstatus):
        name = interface["pfsense"]
        ename = interface["unifi"]
        stat = if_stats[name]
        counter = io_counters[name]
        mac = utils.get_macaddr(if_addrs,name)
        ipv4 = utils.get_ipv4addr(if_addrs,name)
        dpinger = dpingerStatuses[name] if dpingerStatuses.has_key('name') else None
        isup = stat.isup
        
        if interface.has_key("pfsense-ppp") and interface["pfsense-ppp"] is not None:
            ipv4 = utils.get_ipv4addr(if_addrs,interface["pfsense-ppp"])
            dpinger = dpingerStatuses[interface["pfsense-ppp"]] if dpingerStatuses.has_key(interface["pfsense-ppp"]) else dpinger
            isup = if_stats[interface["pfsense-ppp"]].isup if if_stats.has_key(interface["pfsense-ppp"]) else False
        
        ipaddress1 = ipv4.address if ipv4 is not None else "0.0.0.0"
        ntopstat = hostsstatus[ipaddress1] if hostsstatus is not None and  hostsstatus.has_key(ipaddress1) else None

        data = {
                "drops": counter.dropout+counter.dropin,
                "enable": True,
                "full_duplex": stat.duplex==2,
                "gateways": [ dpinger['gateway'] if dpinger is not None else ""  ],
                "ip": ipaddress1,
                "latency": dpinger['latency_stddev'] if dpinger is not None else 0,
                "mac": mac.address,
                "name": ename,
                "nameservers": pfsense_utils.get_dns_servers() if  interface["wan"] else [],
                "netmask": ipv4.netmask if ipv4 is not None else "",
                "num_port": 0,
                "rx_bytes": counter.bytes_recv,
                "rx_dropped": counter.dropin,
                "rx_errors": counter.errin,
                "rx_multicast": 0,
                "rx_packets": counter.packets_recv,
                "speed": stat.speed,
                "tx_bytes": counter.bytes_sent,
                "tx_dropped": counter.dropout,
                "tx_errors": counter.errout,
                "tx_packets": counter.packets_sent,
                "up": isup ,
                "uptime": ntopstat['duration'] if ntopstat is not None and ntopstat.has_key('duration') else 0
                
                }

        if interface["wan"] and ipv4:
            self.wan_addresses.append(ipv4.address)

        return data

    def append_if_table(self,data,if_stats,io_counters,if_addrs,dpingerStatuses,hostsstatus):
        data['if_table']=[]
        for interface in self.mapConfig["ports"]:
            if interface["enabled"] and interface["pfsense"] is not "" :
                data['if_table'].append(self.create_if_element(interface,if_stats,io_counters,if_addrs,dpingerStatuses,hostsstatus))
            else:
                data['if_table'].append({
                "enable": interface["enabled"],
                "name": interface["unifi"]
                })

    def create_host_table_element(self,host):
      data={
            "age": host['duration'],
            "authorized": "True",
            "bc_bytes": 0,
            "bc_packets": 0,
            "dev_cat": 1,
            "dev_family": host['devtype'],
            "dev_id": host['devtype'],
            "dev_vendor": host['devtype'],
            "ip": host['ip'],
            "mac": host['mac'].replace('-',':').lower(),
            "mc_bytes": 0,
            "mc_packets": 0,
            "os_class": host['operatingSystem'],
            "os_name": host['os'],
            "rx_bytes": host['bytes.sent'],
            "rx_packets": host['packets.sent'],
            "tx_bytes": host['bytes.rcvd'],
            "tx_packets": host['packets.rcvd'],
            "uptime": host['seen.last']-host['seen.first']
            }
      return data  

    def create_network_table_element(self,interface,if_stats,io_counters,if_addrs,dpingerStatuses,hostsstatus):
        name = interface["pfsense"]
        ename = interface["unifi"]
        stat = if_stats[name]
        counter = io_counters[name]
        mac = utils.get_macaddr(if_addrs,name)
        ipv4 = utils.get_ipv4addr(if_addrs,name)
        dpinger = dpingerStatuses[name] if dpingerStatuses.has_key('name') else None
        isup = stat.isup
        if interface.has_key("pfsense-ppp") and interface["pfsense-ppp"] is not None:
            ipv4 = utils.get_ipv4addr(if_addrs,interface["pfsense-ppp"])
            dpinger = dpingerStatuses[interface["pfsense-ppp"]] if dpingerStatuses.has_key(interface["pfsense-ppp"]) else dpinger
            isup = if_stats[interface["pfsense-ppp"]].isup if if_stats.has_key(interface["pfsense-ppp"]) else False
        ipaddress1 = ipv4.address if ipv4 is not None else "0.0.0.0"
        ntopstat = hostsstatus[ipaddress1] if  hostsstatus is not None and  hostsstatus.has_key(ipaddress1) else None

        data = {
                "autoneg": "True",
                "duplex": "full" if stat.duplex==2 else "half",
                "l1up": "True",
                "mac": mac.address,
                "mtu": stat.mtu, 
                "name": ename,
                "nameservers": pfsense_utils.get_dns_servers() if  interface["wan"] else [],
                "speed": stat.speed,
                "stats": {
                    "multicast": "0",
                    "rx_bps": "0",
                    "rx_bytes": counter.bytes_recv,
                    "rx_dropped": counter.dropin,
                    "rx_errors": counter.errin,
                    "rx_multicast": 0,
                    "rx_packets": counter.packets_recv,
                    "tx_bps": "0",
                    "tx_bytes": counter.bytes_sent,
                    "tx_dropped": counter.dropout,
                    "tx_errors": counter.errout,
                    "tx_packets": counter.packets_sent
                },
                "up": isup
                }
   
        if (self.config.has_key('ntopng')
            and self.config['ntopng'].has_key('enabled')
            and self.config['ntopng']['enabled']
            and self.config['ntopng'].has_key('showhosts')
            and self.config['ntopng']['showhosts']
            and interface.has_key('address') 
            and 'dhcp' not in interface['address']):
            
            data["address"]= interface['address'][0]
            data["addresses"]= interface['address']
            mask = interface['address'][0]
            calc = ip_calculator.IPCalculator(mask)

            netname = calc.net_name()
            if(hostsstatus is not None):
                hosts = [host for key,host in hostsstatus.items() if host['local_network_name'] == netname and not host['is_broadcast'] and not host['is_multicast']]
                data['host_table']=[]
                for rhost in hosts:
                    data['host_table'].append(self.create_host_table_element(rhost))
                
        if (interface["wan"] or  ( interface.has_key('address') and 'dhcp' in interface['address'])) and ipv4 is not None:
            data["address"]= ipv4.address+"/32"
            data["addresses"]= [ipv4.address+"/32"]
            data["gateways"]=[ dpinger['gateway'] if dpinger is not None else ""  ]
        
        return data
   
    def append_network_table(self,data,if_stats,io_counters,if_addrs,dpingerStatuses,hostsstatus):
         data['network_table']=[]
         for interface in self.mapConfig["ports"]:
              if interface["enabled"] and interface["pfsense"] is not "" :
                  data['network_table'].append(self.create_network_table_element(interface,if_stats,io_counters,if_addrs,dpingerStatuses,hostsstatus))
        
    def append_port_table(self,data,if_stats,io_counters,if_addrs):
        data["config_port_table"]= [
            {
            "ifname": "eth3",
            "name": "wan"
            },
            {
            "ifname": "eth0",
            "name": "lan"
            },
            {
            "ifname": "eth2",
            "name": "wan2"
            }
        ]
          
    def appendExtraInformMessage(self,data):
        data["has_dpi"]=True
        data["has_ssh_disable"]=True
        data["has_vti"]=True
        data["fw_caps"]=3
        data["usg_caps"]=0xFFFF
        data["has_default_route_distance"]=True
        data["has_dnsmasq_hostfile_update"]=True
        data["radius_caps"]=1
        data["has_temperature"]=True
        data["has_fan"]=True
        data["general_temperature"]=30
        data["fan_level"]=20

        if_stats = psutil.net_if_stats()
        io_counters = psutil.net_io_counters(pernic=True)
        if_addrs = psutil.net_if_addrs()
        dpingerStatuses = pfsense_utils.getGatewaysPingerStatus()
        hostsstatus= {}
        if (self.config.has_key('ntopng') 
            and self.config['ntopng'].has_key('enabled') 
            and self.config['ntopng']['enabled']  
            and self.config['ntopng'].has_key('user') 
            and self.config['ntopng'].has_key('password')
            and self.config['ntopng'].has_key('url')
            and self.config['ntopng']['url'] 
            and self.config['ntopng']['user'] 
            and self.config['ntopng']['password']):
          hostsstatus = pfsense_utils.get_ntopng_stats(self.config['ntopng']['user'],self.config['ntopng']['password'],self.config['ntopng']['url'])
          try:
            hostsstatus = json.loads(hostsstatus,object_hook= utils._byteify) if hostsstatus is not None else {}
          except Exception as ex:
            logging.warn(ex)
            hostsstatus = {}

        del self.wan_addresses[:]

        self.appendVPN(data,if_stats,io_counters,if_addrs)
        self.appendWAN(data,if_stats,io_counters,if_addrs)
        self.append_port_table(data,if_stats,io_counters,if_addrs)
        self.append_if_table(data,if_stats,io_counters,if_addrs,dpingerStatuses,hostsstatus)
        self.append_network_table(data,if_stats,io_counters,if_addrs,dpingerStatuses,hostsstatus)
       
    def process_or_create_if(self,key,data):
        tmp = [port for port in self.mapConfig['ports'] if port['unifi'] == key]
        local = None
        if(len(tmp)>0):
            local = tmp[0]
        else:
            local={
                    'unifi':key,
                    'unifi-description':data['description'] if data.has_key('description') else "LAN",
                    'pfsense':'',
                    'enabled':True,
                    'wan':False
                }
            self.mapConfig['ports'].append(local)    

        if(local is not None):
            if(data.has_key('address')):
                local['address']=data['address']
            local['pppoe']=data.has_key('pppoe')
            local['enabled']=not data.has_key('disable') 
   
    def createInterfaces(self,data):
        if(data['interfaces'] is not None and data['interfaces']['ethernet'] is not None):
            for key in data['interfaces']['ethernet']:
                current =  data['interfaces']['ethernet'][key]
                self.process_or_create_if(key,current)
                if(current.has_key('vif')):
                    for vkey in current['vif']:
                        self.process_or_create_if("{}.{}".format(key,vkey),current['vif'][vkey])
        self.save_map()        
    
    def process_command(self,data):
      if(data['cmd']=='speed-test'):
          self.config['speed-test']=data
          self.save_config()
          self.reload_config()
          thread.start_new_thread( self.speedtest_check ,() )

    def speedtest_check(self):
        from speedtest import Speedtest
        self.interval = 1000*100
        cmd = self.createBaseInform()
        cmd['sys_stats']=self.get_sys_stats()
        cmd['system-stats']=self.get_system_stats()

        cmd["speedtest-status"]= {
                                "latency": 0,
                                "rundate": time.time(),
                                "runtime": time.time(),
                                "status_download":0,
                                "status_ping": 11,
                                "status_summary": 1,
                                "status_upload": 0,
                                "xput_download": 0,
                                "xput_upload": 0,
                                "upload-progress":[],
                                "download-progress":[]
                            }
        status = cmd["speedtest-status"]

        self._send_inform(cmd,False)
        speedtest = Speedtest(source_address=self.wan_addresses)
        speedtest.get_best_server()
        results = speedtest.results
        status["latency"] = results.server["latency"]
        status["status_ping"] = 2
        status["status_download"] = 1

        logging.debug('Hosted by %(sponsor)s (%(name)s) [%(d)0.2f km]: '
            '%(latency)s ms' % results.server)

        self._send_inform(cmd,False)
        def download_callback(thread, count, end=False,start=False):
          if(end):
              cmd["speedtest-status"]["xput_download"]=(results.download / 1000.0 / 1000.0)
              cmd["speedtest-status"]["download-progress"] =[
                {"records":[ [time.time(),(results.download / 1000.0 / 10.0)] ]}
              ]
              self._send_inform(cmd,False)

        def upload_callback(thread, count, end=False,start=False):
          if(end):
              cmd["speedtest-status"]["xput_upload"]=(results.upload / 1000.0 / 1000.0)
              cmd["speedtest-status"]["upload-progress"] =[
                {"records":[ [time.time(),(results.upload / 1000.0 / 10.0)] ]}
              ]
              self._send_inform(cmd,False)

        speedtest.download( callback=download_callback)
        logging.debug('Download: %0.2f M/s' %
                ((results.download / 1000.0 / 1000.0)))
        cmd["speedtest-status"]["xput_download"]=(results.download / 1000.0 / 1000.0)
        cmd["speedtest-status"]["status_download"]=2
        cmd["speedtest-status"]["download-progress"]=[]

        self._send_inform(cmd,False)        
        speedtest.upload(callback=upload_callback)
        logging.debug('Upload: %0.2f M/s' %
                ((results.upload / 1000.0 / 1000.0)))

        cmd["speedtest-status"]["status_summary"]=2
        cmd["speedtest-status"]["status_upload"]=2
        cmd["speedtest-status"]["upload-progress"]=[]
        cmd["speedtest-status"]["xput_upload"]=(results.upload / 1000.0 / 1000.0)

        self._send_inform(cmd,False)
        self.delayStart-=self.interval

    def parseResponse(self,data):
        if(data is None):
            return
        
        result = json.loads(data)
        logging.debug("Got message {}".format(result['_type']))
        if result['_type'] == 'setdefault':
            if self.config.has_key("mgmt_cfg"):
                self.config.pop("mgmt_cfg",None)
            self.config['gateway']['is_adopted'] = False
            self.config['gateway']['key'] = ''
            self.config['gateway']['url'] = ''
            self.save_config()
            self.reload_config()

        if result['_type'] == 'upgrade':
            self.config['gateway']['firmware']= result['version']
            self.firmware = result['version']
            self.save_config()
            self.reload_config()

        if result['_type'] == 'cmd': 
            self.process_command(result)

        if result['_type'] == 'noop' and result['interval']: 
            self.interval = 1000*int(result['interval'])

        if result['_type'] == 'setparam':
            for key, value in result.items():
                if key not in ['_type', 'server_time_in_utc', 'mgmt_cfg','system_cfg']:
                    self.config['gateway'][key]= value
                elif key in ['mgmt_cfg']:
                    if not self.config.has_key(key):
                        self.config[key]={}
                    lines = re.split('\n',value) 
                    for line in lines:
                        if not line =='':
                            data = re.split('=',line)
                            self.config[key][data[0]]= data[1]

                elif key in ['system_cfg']:
                    system_cfg = json.loads(value,object_hook= utils._byteify)
                    if system_cfg["system"] is not None and system_cfg["system"].has_key("host-name"):
                        self.config['gateway']['host'] = system_cfg["system"]["host-name"]
                        self.save_config()
                        self.reload_config()
                    with open(self.configfile.replace(".conf",".json"), 'w') as outfile:
                        json.dump(system_cfg, outfile,indent=True)
                    self.createInterfaces(system_cfg)

            wasAdopted = self.config['gateway']['is_adopted']
            self.config['gateway']['is_adopted']=True
            self.save_config()
            self.reload_config()
            cmd = self.createNotify('setparam','')
            if not wasAdopted:
                cmd['discovery_response']= True
            self.nextCommand = basecommand.BaseCommand(basecommand.CMD_NOTIFY,cmd)
            self.delayStart-=self.interval
                    
