# coding: utf-8
from basedevice import BaseDevice
import basecommand 
import json
import re
class UnifiUSG(BaseDevice):
    def __init__(self,config,configfile):
        BaseDevice.__init__(self,config.get('gateway', 'lan_mac'),config.get('gateway', 'lan_ip'),config.get('gateway', 'firmware'),'UGW3','UniFi-Gateway-3')
        self.config = config
        self.configfile = configfile
        
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

    def _save_config(self):
        with open(self.configfile, 'w') as config_file:
            self.config.write(config_file)
    
    def parseResponse(self,data):
        result = json.loads(data)
        if result['_type'] == 'setparam':
            for key, value in result.items():
                if key not in ['_type', 'server_time_in_utc', 'mgmt_cfg','system_cfg']:
                    self.config.set('gateway', key, value)
                elif key not in ['_type', 'server_time_in_utc']:
                    if not self.config.has_section(key):
                        self.config.add_section(key)
                    lines = re.split('\n',value) 
                    for line in lines:
                        if not line =='':
                            data = re.split('=',line) 
                            self.config.set(key, data[0], data[1]) 
            wasAdopted = self.config.getboolean('gateway', 'is_adopted')
            self.config.set('gateway', 'is_adopted', 'yes')
            self._save_config()
            self.config.read(self.configfile)
            self.nextCommand = basecommand.BaseCommand(basecommand.CMD_NOTIFY,self.createNotify(wasAdopted))
            self.delayStart-=self.interval
                    
