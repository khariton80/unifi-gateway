# -*- coding: utf-8 -*-
from loggerinitializer import *
import sys
import ConfigParser
import argparse
# import re
import logging.handlers
# import socket
# import time
# import urllib2
# import json
# from daemon import Daemon
# from unifi.stun import *
# import unifi.cryptoutils 
# from unifi_protocol import create_broadcast_message, create_inform, encode_inform, decode_inform

import time
import unifi.unifi_usg
delayStart =0;
CONFIG_FILE = 'conf/unifi-gateway.conf'
initialize_logger('./logs')
class UnifiConsole():

    def __init__(self, **kwargs):
        self.interval = 10 * 1000
        self.config = ConfigParser.RawConfigParser()
        self.config.read(CONFIG_FILE)
        global delayStart
        delayStart = int(round(time.time()  * 1000)) - self.interval
        if(kwargs.has_key('mode')):
            if kwargs['mode']=='usg':
                self.device = unifi.unifi_usg.UnifiUSG(self.config)
            elif kwargs['mode']=='ap':
                self.device = unifi.unifi_usg.BaseDevice()
            else: 
                self.device = unifi.unifi_usg.UnifiUSG(self.config)  
        else:
            self.device = unifi.unifi_usg.UnifiUSG(self.config);    

        #Daemon.__init__(self, pidfile=self.config.get('global', 'pid_file'), **kwargs)

    def run(self):
        global delayStart
        while True:
            if (int(round(time.time()*1000))-delayStart)>=self.interval :
                logging.debug("tick")
                self.device.sendinfo()
                delayStart = int(round(time.time()*1000))
                time.sleep(0.1)
    
    def set_adopt(self, url, key):
        pass

    def _save_config(self):
        with open(CONFIG_FILE, 'w') as config_file:
            self.config.write(config_file)

def processargs(args):
    global console
    console = UnifiConsole(mode=args.mode)

def restart(args):
    processargs(args)
    console.restart()


def stop(args):
    processargs(args)
    console.stop()


def start(args):
    processargs(args)
    console.start()

def run(args):
    processargs(args)
    console.run()

def set_adopt(args):
    processargs(args)
    url, key = args.s, args.k
    console.set_adopt(url, key)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', type=str, help='key',default='usg' )
    parser.set_defaults(func=processargs)
    subparsers = parser.add_subparsers()

    parser_adopt = subparsers.add_parser('run', help='send the adoption request to the controller')
    parser_adopt.set_defaults(func=run)
    parser_adopt = subparsers.add_parser('restart', help='send the adoption request to the controller')
    parser_adopt = subparsers.add_parser('stop', help='send the adoption request to the controller')
    parser_adopt = subparsers.add_parser('start', help='send the adoption request to the controller')

    parser_adopt = subparsers.add_parser('set-adopt', help='send the adoption request to the controller')
    parser_adopt.add_argument('-s', type=str, help='controller url', required=True)
    parser_adopt.add_argument('-k', type=str, help='key', required=True)
    parser_adopt.set_defaults(func=set_adopt)
    args = parser.parse_args()

    args.func(args)
    #console.run()
