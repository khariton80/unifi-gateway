# coding: utf-8
import functools
import os.path, time
import xml.etree.ElementTree as ET
def config_checker(func):
    @functools.wraps(func)
    def wrapper_decorator(*args, **kwargs):
        args[0].ckeckConfig()
        value = func(*args, **kwargs)
        return value
    return wrapper_decorator
class PfsenseConfig(object):
    def __init__(self,config):
        self.configFile = config
        self.configModifiedDate = os.path.getmtime(self.configFile)
        self.loadConfig()
    
    def ckeckConfig(self):
        if self.configModifiedDate < os.path.getmtime(self.configFile):
            print ("Config old date={} newdate={}".format(self.configModifiedDate,os.path.getmtime(self.configFile)))
            self.loadConfig()

    def loadConfig(self):
        tree = ET.parse(self.configFile)
        self.root = tree.getroot()
        self.interfaces=[]
        ifs = self.root.find("./interfaces")
        if ifs is not None:
            for child in ifs._children:
                self.interfaces.append({
                    child.tag:{
                        "if":child.find("if").text,
                        "descr":child.find("descr").text,
                        "enable":child.find("enable") is not None,
                        "ipaddr":child.find("ipaddr").text if child.find("ipaddr") is not None else "",
                        "subnet":child.find("subnet").text if child.find("subnet") is not None else ""
                        }
                })

    @config_checker
    def printData(self):
        for child in self.interfaces:
            print child.keys()

    @config_checker
    def getDefaultLan(self):
        tmp = [iface for iface in self.interfaces if 'lan' in iface.keys()]
        return tmp[0].values()[0] if len(tmp)>0 else None
    @config_checker
    def getDefaultWan(self):
        tmp = [iface for iface in self.interfaces if 'wan' in iface.keys()]
        return tmp[0].values()[0] if len(tmp)>0 else None



