# -*- coding: utf-8 -*-
from unifi.stun import *

if __name__ == '__main__':
    while True:
            
        client = StunClient()
        client.send_request('192.168.1.4',3478)
        result = client.receive_response()
        print result
        client.close()

        for item in result: 
            if 'MAPPED-ADDRESS' == item['name']:
                print item
       

        #time.sleep(10)
