# coding: utf-8
from basedevice import BaseDevice
import basecommand 
import json
import re
import psutil
class UnifiUSG(BaseDevice):
    def __init__(self,configfile):
        BaseDevice.__init__(self,'UGW4','UniFi-Gateway-3',configfile)
                
    def cfgversion(self):
        if self.config.has_section('mgmt_cfg') and self.config.has_option('mgmt_cfg','cfgversion'):
            print(self.config.get('mgmt_cfg', 'cfgversion')) 
            return self.config.get('mgmt_cfg', 'cfgversion')     
        else:
            return "?"    
    def version(self):
        return self.config.get('mgmt_cfg', 'cfgversion')       
    def getCurrentMessageType(self):
        if self.config.has_section('gateway') and not self.config.getboolean('gateway', 'is_adopted') and self.config.get('gateway', 'key')=="" :
            return -1     
        if self.config.has_section('gateway') and not self.config.getboolean('gateway', 'is_adopted') and not self.config.get('gateway', 'key')=="" : #discover
            return 1     
        if self.config.has_section('gateway') and self.config.getboolean('gateway', 'is_adopted') : #info
            return 2     
    def getInformUrl(self):
        return self.config.get('gateway', 'url')
    def getInformIp(self):
        return "192.168.106.172"                      
    def getHostname(self):
        return "UBNT"      
    def getKey(self):
        return self.config.get('gateway', 'key')

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
        data["config_network_w2"]={
            "dns1": "10.1.1.1",
            "gateway": "10.1.1.1",
            "ip": "10.1.1.10",
            "netmask": "255.255.255.0",
            "type": "static"
        }

    def create_if_element(self,name,if_stats,io_counters,if_addrs,ename,ip,mac,numport):
        stat = if_stats[name]
        counter = io_counters[name]
        addr = if_addrs[name]
        data = {
                "drops": 333,
                "enable": True,
                "full_duplex": stat.duplex==2,
                "gateways": [
                    "20.1.2.3"
                ],
                "ip": ip,
                "latency": 11,
                "mac": mac,
                "name": ename,
                "nameservers": [
                    "20.1.2.19",
                    "20.1.3.19"
                ],
                "netmask": "255.255.255.0",
                "num_port": numport,
                "rx_bytes": counter.bytes_recv,
                "rx_dropped": counter.dropin,
                "rx_errors": counter.errin,
                "rx_multicast": 65629,
                "rx_packets": counter.packets_recv,
                "speed":100,# stat.speed,
                "speedtest_lastrun": 1583600088374,
                "speedtest_ping": 68,
                "speedtest_status": "Idle",
                "tx_bytes": counter.bytes_sent,
                "tx_dropped": counter.dropout,
                "tx_errors": counter.errout,
                "tx_packets": counter.packets_sent,
                "up": stat.isup or True,
                "uptime": 37193,
                "xput_down": 38.161000000000001,
                "xput_up": 12.484999999999999
                }
        return data

    def append_if_table(self,data,if_stats,io_counters,if_addrs):
        data['if_table']=[ 
            self.create_if_element("Wi-Fi",if_stats,io_counters,if_addrs,"eth3","20.1.2.41","80:2a:a8:cd:a9:52",0),
            self.create_if_element("Wi-Fi",if_stats,io_counters,if_addrs,"eth0","192.168.1.1","80:2a:a8:cd:a9:53",1),
            self.create_if_element("Wi-Fi",if_stats,io_counters,if_addrs,"eth2","20.1.2.10","80:2a:a8:cd:a9:54",2)
        ]   
        data['if_table'].append({
                "drops": 333,
                "enable": False,
                "name": "eth1"
                })
    
    
    def append_network_table(self,data,if_stats,io_counters,if_addrs):
        data["network_table"]= [
                {
                "address": "10.1.1.10/24",
                "addresses": [
                    "10.1.1.10/24"
                ],
                "autoneg": "True",
                "duplex": "full",
                "gateways": [
                    "20.1.2.1"
                ],
                "l1up": "True",
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
                "up": "True"
                },
                {
                "address": "192.168.1.1/24",
                "addresses": [
                    "192.168.1.1/24"
                ],
                "autoneg": "True",
                "duplex": "full",
                "host_table": [
                    {
                    "age": 10,
                    "authorized": "True",
                    "bc_bytes": 4814073447,
                    "bc_packets": 104642338,
                    "dev_cat": 1,
                    "dev_family": 4,
                    "dev_id": 239,
                    "dev_vendor": 47,
                    "ip": "192.168.1.8",
                    "mac": "81:2a:a8:f0:ef:78",
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
                    "authorized": "True",
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
                    }
                ],
                "l1up": "True",
                "mac": "80:2a:a8:cd:a9:53",
                "mtu": "1500",
                "name": "eth0",
                "speed": "1000",
                "stats": {
                    "multicast": "412294",
                    "rx_bps": "34",
                    "rx_bytes": 529472247,
                    "rx_dropped": 2800,
                    "rx_errors": 0,
                    "rx_multicast": 412314,
                    "rx_packets": 3412329,
                    "tx_bps": "250",
                    "tx_bytes": 7922054171,
                    "tx_dropped": 0,
                    "tx_errors": 0,
                    "tx_packets": 5909307
                },
                "up": "True"
                },
                {
                "address": "20.1.2.10/21",
                "addresses": [
                    "20.1.2.10/21"
                ],
                "autoneg": "True",
                "duplex": "full",
                "gateways": [
                    "20.1.1.1"
                ],
                "l1up": "True",
                "mac": "80:2a:a8:cd:a9:52",
                "mtu": "1500",
                "name": "eth3",
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
                "up": "True"
                }
            ]
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
        #data["has_eth1"]=True
        #data["has_porta"]=True
        data["has_ssh_disable"]=True
        data["has_vti"]=True
        data["fw_caps"]=3
        data["has_default_route_distance"]=True
        data["has_dnsmasq_hostfile_update"]=True
        data["radius_caps"]=1
  

        if_stats = psutil.net_if_stats()
        io_counters = psutil.net_io_counters(pernic=True)
        if_addrs = psutil.net_if_addrs()

        self.appendVPN(data,if_stats,io_counters,if_addrs)
        self.appendWAN(data,if_stats,io_counters,if_addrs)
        self.append_port_table(data,if_stats,io_counters,if_addrs)
        self.append_if_table(data,if_stats,io_counters,if_addrs)
        self.append_network_table(data,if_stats,io_counters,if_addrs)
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
        
               
        
      
    def _save_config(self):
        with open(self.configfile, 'w') as config_file:
            self.config.write(config_file)
    
    def parseResponse(self,data):
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
        if result['_type'] == 'setparam':
            for key, value in result.items():
                if key not in ['_type', 'server_time_in_utc', 'mgmt_cfg','system_cfg']:
                    self.config.set('gateway', key, value)
                elif key in ['mgmt_cfg']:
                    if not self.config.has_section(key):
                        self.config.add_section(key)
                    lines = re.split('\n',value) 
                    for line in lines:
                        if not line =='':
                            data = re.split('=',line) 
                            self.config.set(key, data[0], data[1]) 
                elif key in ['system_cfg']:
                    system_cfg = json.loads(value)
                    with open(self.configfile.replace(".conf",".json"), 'w') as outfile:
                        json.dump(system_cfg, outfile,indent=True)

            wasAdopted = self.config.getboolean('gateway', 'is_adopted')
            self.config.set('gateway', 'is_adopted', 'yes')
            self._save_config()
            self.config.read(self.configfile)
            cmd = self.createNotify('setparam','')
            if not wasAdopted:
                cmd['discovery_response']= True
            self.nextCommand = basecommand.BaseCommand(basecommand.CMD_NOTIFY,cmd)
            self.delayStart-=self.interval
                    
