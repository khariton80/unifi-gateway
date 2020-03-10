# -*- coding: utf-8 -*-
from loggerinitializer import *
import sys
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
import unifi.unifi_usg_pro
import unifi.unifi_ap_lite
import unifi.utils
CONFIG_FILE = 'conf/unifi-gateway.conf.json'
class UnifiConsole():

    def __init__(self, **kwargs):
               
        if(kwargs.has_key('mode')):
            if kwargs['mode']=='usg':
                self.device = unifi.unifi_usg.UnifiUSG(kwargs['config'])
            elif kwargs['mode']=='usgp':
                self.device = unifi.unifi_usg_pro.UnifiUSGPro(kwargs['config'])
            elif kwargs['mode']=='ap':
                self.device = unifi.unifi_ap_lite.UnifiAPLite(kwargs['config'])
            else: 
                self.device = unifi.unifi_usg.UnifiUSG(kwargs['config'])  
        else:
            self.device = unifi.unifi_usg.UnifiUSG(kwargs['config']);    

    def run(self):
        while True:
            if (int(time.time()*1000)-self.device.delayStart)>=self.device.interval :
                self.device.delayStart = int(round(time.time()*1000))
                self.device.reload_config()
                logging.debug("tick")
                self.device.sendinfo()
            time.sleep(0.1)
  

def processargs(args):
    global console
    console = UnifiConsole(mode=args.mode, config=args.config)

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
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)

    initialize_logger('logs')
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', type=str, help='key',default='usg' )
    parser.add_argument('--config', type=str, help='key',default=CONFIG_FILE )
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
