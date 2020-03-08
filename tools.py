# -*- coding: utf-8 -*-

import psutil
def mac_string_2_array(mac):
    return [int(i, 16) for i in mac.split(':')]


def ip_string_2_array(mac):
    return [int(i) for i in mac.split('.')]

    print psutil.net_if_stats()
