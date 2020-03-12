# coding: utf-8
from basedevice import BaseDevice
import basecommand 
import json
import re
import psutil
import utils
import pfsense_utils
class UnifiUSGPro(BaseDevice):
    def __init__(self,configfile):
        BaseDevice.__init__(self,'UGW4','UniFi-Gateway-3',configfile)
                
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

    def create_if_element(self,interface,if_stats,io_counters,if_addrs,dpingerStatuses):
        name = interface["pfsense"]
        ename = interface["unifi"]
        stat = if_stats[name]
        counter = io_counters[name]
        mac = utils.get_macaddr(if_addrs,name)
        ipv4 = utils.get_ipv4addr(if_addrs,name)
        dpinger = dpingerStatuses[name] if dpingerStatuses.has_key('name') else None
        
        if interface.has_key("pfsense-ppp") and interface["pfsense-ppp"] is not None:
            ipv4 = utils.get_ipv4addr(if_addrs,interface["pfsense-ppp"])
            dpinger = dpingerStatuses[interface["pfsense-ppp"]] if dpingerStatuses.has_key(interface["pfsense-ppp"]) else dpinger
            #stat = if_stats[interface["pfsense-ppp"]]
            #counter = io_counters[interface["pfsense-ppp"]]
        data = {
                "drops": counter.dropout+counter.dropin,
                "enable": True,
                "full_duplex": stat.duplex==2,
                "gateways": [ dpinger['gateway'] if dpinger is not None else ""  ],
                "ip": ipv4.address if ipv4 is not None else "0.0.0.0",
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
                "speedtest_lastrun": 1583600088374,
                "speedtest_ping": 68,
                "speedtest_status": "Idle",
                "tx_bytes": counter.bytes_sent,
                "tx_dropped": counter.dropout,
                "tx_errors": counter.errout,
                "tx_packets": counter.packets_sent,
                "up": stat.isup ,
                "uptime": 37193,
                "xput_down": 38.161000000000001,
                "xput_up": 12.484999999999999
                }
        return data

    def append_if_table(self,data,if_stats,io_counters,if_addrs,dpingerStatuses):
        data['if_table']=[]
        for interface in self.mapConfig["ports"]:
            if interface["enabled"] and interface["pfsense"] is not "" :
                data['if_table'].append(self.create_if_element(interface,if_stats,io_counters,if_addrs,dpingerStatuses))
            else:
                data['if_table'].append({
                "enable": interface["enabled"],
                "name": interface["unifi"]
                })
    
    def create_network_table_element(self,interface,if_stats,io_counters,if_addrs,dpingerStatuses):
        name = interface["pfsense"]
        ename = interface["unifi"]
        stat = if_stats[name]
        counter = io_counters[name]
        mac = utils.get_macaddr(if_addrs,name)
        ipv4 = utils.get_ipv4addr(if_addrs,name)
        dpinger = dpingerStatuses[name] if dpingerStatuses.has_key('name') else None
        
        if interface.has_key("pfsense-ppp") and interface["pfsense-ppp"] is not None:
            ipv4 = utils.get_ipv4addr(if_addrs,interface["pfsense-ppp"])
            dpinger = dpingerStatuses[interface["pfsense-ppp"]] if dpingerStatuses.has_key(interface["pfsense-ppp"]) else dpinger
            #stat = if_stats[interface["pfsense-ppp"]]
            #counter = io_counters[interface["pfsense-ppp"]]
                # "address": addr,
                # "addresses": [
                #     addr
                # ],

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
                "up": stat.isup
                }
   
        if(interface.has_key('address')):
            data["address"]= interface['address'][0]
            data["addresses"]= interface['address']
                
        if interface["wan"] or  ( interface.has_key('address') and 'dhcp' in interface['address']):
            data["address"]= ipv4.address+"/32"
            data["addresses"]= [ipv4.address+"/32"]
            data["gateways"]=[ dpinger['gateway'] if dpinger is not None else ""  ]
        
        return data
    def append_network_table(self,data,if_stats,io_counters,if_addrs,dpingerStatuses):
         data['network_table']=[]
         for interface in self.mapConfig["ports"]:
              if interface["enabled"] and interface["pfsense"] is not "" :
                  data['network_table'].append(self.create_network_table_element(interface,if_stats,io_counters,if_addrs,dpingerStatuses))
        #      else:
        #          data['network_table'].append({
        #          "enable": interface["enabled"],
        #          "name": interface["unifi"]
        #          })
        # data["network_table"]= [
        #         {
        #         "address": "10.1.1.10/24",
        #         "addresses": [
        #             "10.1.1.10/24"
        #         ],
        #         "autoneg": "True",
        #         "duplex": "full",
        #         "gateways": [
        #             "20.1.2.1"
        #         ],
        #         "l1up": "True",
        #         "mac": "80:2a:a8:cd:a9:54",
        #         "mtu": "1500",
        #         "name": "eth2",
        #         "nameservers": [
        #             "20.1.2.191",
        #             "20.1.3.191"
        #         ],
        #         "speed": "1000",
        #         "stats": {
        #             "multicast": "65627",
        #             "rx_bps": "0",
        #             "rx_bytes": 118162997,
        #             "rx_dropped": 1,
        #             "rx_errors": 0,
        #             "rx_multicast": 65629,
        #             "rx_packets": 1126891,
        #             "tx_bps": "0",
        #             "tx_bytes": 77684158,
        #             "tx_dropped": 0,
        #             "tx_errors": 0,
        #             "tx_packets": 1025525
        #         },
        #         "up": "True"
        #         },
        #         {
        #         "address": "192.168.1.1/24",
        #         "addresses": [
        #             "192.168.1.1/24"
        #         ],
        #         "autoneg": "True",
        #         "duplex": "full",
        #         "host_table": [
        #             {
        #             "age": 10,
        #             "authorized": "True",
        #             "bc_bytes": 4814073447,
        #             "bc_packets": 104642338,
        #             "dev_cat": 1,
        #             "dev_family": 4,
        #             "dev_id": 239,
        #             "dev_vendor": 47,
        #             "ip": "192.168.1.8",
        #             "mac": "81:2a:a8:f0:ef:78",
        #             "mc_bytes": 4814073447,
        #             "mc_packets": 104642338,
        #             "os_class": 15,
        #             "os_name": 19,
        #             "rx_bytes": 802239963372,
        #             "rx_packets": 805925675,
        #             "tx_bytes": 35371476651,
        #             "tx_packets": 104136843,
        #             "uptime": 5822032
        #             },
        #             {
        #             "age": 41,
        #             "authorized": "True",
        #             "bc_bytes": 9202676,
        #             "bc_packets": 200043,
        #             "hostname": "switch",
        #             "ip": "192.168.1.10",
        #             "mac": "f0:9f:c2:09:2b:f2",
        #             "mc_bytes": 21366640,
        #             "mc_packets": 406211,
        #             "rx_bytes": 30862046,
        #             "rx_packets": 610310,
        #             "tx_bytes": 13628015,
        #             "tx_packets": 204110,
        #             "uptime": 5821979
        #             }
        #         ],
        #         "l1up": "True",
        #         "mac": "80:2a:a8:cd:a9:53",
        #         "mtu": "1500",
        #         "name": "eth0",
        #         "speed": "1000",
        #         "stats": {
        #             "multicast": "412294",
        #             "rx_bps": "34",
        #             "rx_bytes": 529472247,
        #             "rx_dropped": 2800,
        #             "rx_errors": 0,
        #             "rx_multicast": 412314,
        #             "rx_packets": 3412329,
        #             "tx_bps": "250",
        #             "tx_bytes": 7922054171,
        #             "tx_dropped": 0,
        #             "tx_errors": 0,
        #             "tx_packets": 5909307
        #         },
        #         "up": "True"
        #         },
        #         {
        #         "address": "20.1.2.10/21",
        #         "addresses": [
        #             "20.1.2.10/21"
        #         ],
        #         "autoneg": "True",
        #         "duplex": "full",
        #         "gateways": [
        #             "20.1.1.1"
        #         ],
        #         "l1up": "True",
        #         "mac": "80:2a:a8:cd:a9:52",
        #         "mtu": "1500",
        #         "name": "eth3",
        #         "nameservers": [
        #             "20.1.2.1",
        #             "20.1.2.11"
        #         ],
        #         "speed": "1000",
        #         "stats": {
        #             "multicast": "65627",
        #             "rx_bps": "262",
        #             "rx_bytes": 353519562926,
        #             "rx_dropped": 19137,
        #             "rx_errors": 0,
        #             "rx_multicast": 65629,
        #             "rx_packets": 645343103,
        #             "tx_bps": "328",
        #             "tx_bytes": 953646055362,
        #             "tx_dropped": 0,
        #             "tx_errors": 0,
        #             "tx_packets": 863173990
        #         },
        #         "up": "True"
        #         }
        #     ]
    def append_port_table(self,data,if_stats,io_counters,if_addrs):
        #data['if_table']=[]
        #for interface in self.mapConfig["ports"]:
            
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
        #data["has_eth1"]=True
        #data["has_porta"]=True
        data["has_ssh_disable"]=True
        data["has_vti"]=True
        data["fw_caps"]=3
        data["usg_caps"]=9
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

        self.appendVPN(data,if_stats,io_counters,if_addrs)
        self.appendWAN(data,if_stats,io_counters,if_addrs)
        self.append_port_table(data,if_stats,io_counters,if_addrs)
        self.append_if_table(data,if_stats,io_counters,if_addrs,dpingerStatuses)
        self.append_network_table(data,if_stats,io_counters,if_addrs,dpingerStatuses)
       
               
        
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
    def parseResponse(self,data):
        if(data is None):
            return
        
        result = json.loads(data)
        print("Got message {}".format(result['_type']))
        if result['_type'] == 'setdefault':
            if self.config.has_section("mgmt_cfg"):
                self.config.remove_section("mgmt_cfg")
            self.config.set('gateway', 'is_adopted', 'no')
            self.config.set('gateway', 'key', '')
            self.config.set('gateway', 'url', '')
            self._save_config()
            self.config.read(self.configfile)
        if result['_type'] == 'upgrade':
            self.config['gateway']['firmware']= result['version']
            self.firmware = result['version']
            self.save_config()
            self.reload_config()
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
                    
