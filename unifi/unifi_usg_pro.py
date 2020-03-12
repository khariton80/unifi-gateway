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
        data["dpi-stats"]= [
    {
      "initialized": "94107792805",
      "mac": "00:26:4a:08:d6:0c",
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
  ]
        data["dpi-stats-table"]= [
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
              "mac": "f4:1b:a1:d8:55:33",
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
              "mac": "f4:1b:a1:d8:55:33",
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
              "mac": "f4:1b:a1:d8:55:33",
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
              "mac": "f4:1b:a1:d8:55:33",
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
              "mac": "f4:1b:a1:d8:55:33",
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
              "mac": "f4:1b:a1:d8:55:33",
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
              "mac": "f4:1b:a1:d8:55:33",
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
              "mac": "f4:1b:a1:d8:55:33",
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
              "mac": "f4:1b:a1:d8:55:33",
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
              "mac": "f4:1b:a1:d8:55:33",
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
              "mac": "f4:1b:a1:d8:55:33",
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
              "mac": "f4:1b:a1:d8:55:33",
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
              "mac": "f4:1b:a1:d8:55:33",
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
              "mac": "f4:1b:a1:d8:55:33",
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
              "mac": "f4:1b:a1:d8:55:33",
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
              "mac": "f4:1b:a1:d8:55:33",
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
  ]
  

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
                    
