# coding: utf-8
from basedevice import BaseDevice
class UnifiUSG(BaseDevice):
    def __init__(self,config):
        BaseDevice.__init__(self,config.get('gateway', 'lan_mac'),config.get('gateway', 'lan_ip'),config.get('gateway', 'firmware'),'UGW3','')
        self.modelDisplay='UniFi-Gateway-3'
        
        
    def create_broadcast_message1(self,index, version=2, command=6):
        tlv = UnifiTLV()
        tlv.add(1, bytearray(mac_string_2_array(self.mac)))
        tlv.add(2, bytearray(mac_string_2_array(self.mac) + ip_string_2_array(self.ip)))
        tlv.add(3, bytearray('{}.v{}'.format(self.device, self.firmware)))
        tlv.add(10, bytearray([ord(c) for c in pack('!I', getuptime())]))
        tlv.add(11, bytearray('UBNT'))
        tlv.add(12, bytearray(device))
        tlv.add(19, bytearray(mac_string_2_array(lan_mac)))
        tlv.add(18, bytearray([ord(c) for c in pack('!I', index)]))
        tlv.add(21, bytearray(device))
        tlv.add(27, bytearray(firmware))
        tlv.add(22, bytearray(firmware))
        return tlv.get(version=version, command=command)   