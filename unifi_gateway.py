# -*- coding: utf-8 -*-
import ConfigParser
import argparse
import re
import logging.handlers
import socket
import time
import urllib2
import json
from daemon import Daemon
import stun
from unifi_protocol import create_broadcast_message, create_inform, encode_inform, decode_inform

#handler = logging.handlers.SysLogHandler(address='/var/log/test.log')
#handler.setFormatter(logging.Formatter('[unifi-gateway] : %(levelname)s : %(message)s'))

#handler = logging.handlers.. (address='/var/log/test.log')
#handler.setFormatter(logging.Formatter('[unifi-gateway] : %(levelname)s : %(message)s'))
logger = logging.getLogger('unifi-gateway')
logger.setLevel(logging.DEBUG)
#logger.addHandler(handler)

CONFIG_FILE = 'conf/unifi-gateway.conf'


class UnifiGateway():

    def __init__(self, **kwargs):
        self.interval = 10
        self.config = ConfigParser.RawConfigParser()
        self.config.read(CONFIG_FILE)

        #Daemon.__init__(self, pidfile=self.config.get('global', 'pid_file'), **kwargs)

    def run(self):
        broadcast_index = 1
        while self.config.get('gateway', 'key')=="":
            self._send_broadcast(broadcast_index)
            time.sleep(self.interval)
            broadcast_index += 1

        while True:
            #self._send_broadcast(broadcast_index)
            response = self._send_inform(create_inform(self.config))
            logger.debug('Receive {} from controller'.format(response))
            logger.debug('Receive {} from controller'.format(response))
            result = json.loads(response)
            if result['_type'] == 'setparam':
               for key, value in result.items():
                  if key not in ['_type', 'server_time_in_utc', 'mgmt_cfg']:
                    self.config.set('gateway', key, value)
                  if key == 'mgmt_cfg':
                      if not self.config.has_section('mgmt_cfg'):
                          self.config.add_section('mgmt_cfg')
                      lines = re.split('\n',value) 
                      for line in lines:
                          if not line =='':
                                data = re.split('=',line) 
                                self.config.set('mgmt_cfg', data[0], data[1]) 
            self.config.set('gateway', 'is_adopted', 'yes')
            self._save_config()
            # client = stun.StunClient()
            # client.send_request('192.168.1.4',3478)
            # print client.receive_response()
            # client.close()
            
            #nat_type, external_ip, external_port = stun.StunClient.get_ip_info(stun_host='stun.ekiga.net')

            #192.168.1.4:3478
            time.sleep(self.interval)

    def _send_broadcast(self, broadcast_index):
        addrinfo = socket.getaddrinfo('233.89.188.1', None)[0]

        sock = socket.socket(addrinfo[0], socket.SOCK_DGRAM)

        #sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 20,)
        sock.sendto(create_broadcast_message(self.config, broadcast_index), (addrinfo[4][0], 10001))

        logger.debug('Send broadcast message #{} from gateway {}'.format(broadcast_index, self.config.get('gateway', 'lan_ip')))

    def quit(self):
        pass

    def set_adopt(self, url, key):
        self.config.set('gateway', 'url', url)
        self.config.set('gateway', 'key', key)
        self._save_config()

        response = self._send_inform(create_inform(self.config))
        logger.debug('Receive {} from controller'.format(response))
        if response['_type'] == 'setparam':
            for key, value in response.items():
                if key not in ['_type', 'server_time_in_utc', 'mgmt_cfg']:
                    self.config.set('gateway', key, value)
            self.config.set('gateway', 'is_adopted', True)
            self._save_config()

    def _send_inform(self, data):
        print (data)
        headers = {
            'Content-Type': 'application/x-binary',
            'User-Agent': 'AirControl Agent v1.0'
        }
        url = self.config.get('gateway', 'url')

        request = urllib2.Request(url, encode_inform(self.config,data), headers)
        response = urllib2.urlopen(request)
        logger.debug('Send inform request to {} : {}'.format(url, data))
        return decode_inform(self.config, response.read())

    def _save_config(self):
        with open(CONFIG_FILE, 'w') as config_file:
            self.config.write(config_file)


def restart(args):
    UnifiGateway().restart()


def stop(args):
    UnifiGateway().stop()


def start(args):
    UnifiGateway().start()


def set_adopt(args):
    url, key = args.s, args.k
    UnifiGateway().set_adopt(url, key)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_start = subparsers.add_parser('start', help='start unifi gateway daemon')
    parser_start.set_defaults(func=start)

    parser_stop = subparsers.add_parser('stop', help='stop unifi gateway daemon')
    parser_stop.set_defaults(func=stop)

    parser_restart = subparsers.add_parser('restart', help='restart unifi gateway daemon')
    parser_restart.set_defaults(func=restart)

    parser_adopt = subparsers.add_parser('set-adopt', help='send the adoption request to the controller')
    parser_adopt.add_argument('-s', type=str, help='controller url', required=True)
    parser_adopt.add_argument('-k', type=str, help='key', required=True)
    parser_adopt.set_defaults(func=set_adopt)

    #args = parser.parse_args(['set-adopt', '-s', 'http://toto', '-k', 'oeruchoreuch'])
    args = parser.parse_args(['start'])
    #args.func(args)
    UnifiGateway().run()
