# coding: utf-8
from uptime import uptime
import time
import re
import psutil
import ctypes
import struct
import os

global g
g = {
	"event_address" : "unix:///var/run/check_reload_status",
	"factory_shipped_username" : "admin",
	"factory_shipped_password" : "pfsense",
	"upload_path" : "/root",
	"dhcpd_chroot_path" : "/var/dhcpd",
	"unbound_chroot_path" : "/var/unbound",
	"var_path" : "/var",
	"varrun_path" : "/var/run",
	"varetc_path" : "/var/etc",
	"vardb_path" : "/var/db",
	"varlog_path" : "/var/log",
	"etc_path" : "/etc",
	"tmp_path" : "/tmp",
	"tmp_path_user_code" : "/tmp/user_code",
	"conf_path" : "/conf",
	"conf_default_path" : "/conf.default",
	"cf_path" : "/cf",
	"cf_conf_path" : "/cf/conf",
	"www_path" : "/usr/local/www",
	"captiveportal_path" : "/usr/local/captiveportal",
	"captiveportal_element_path" : "/var/db/cpelements"
}



class TLV(object):
    def __init__(self):
        self.results = bytearray()

    def add(self, type, value):
        data = bytearray([type, ((len(value) >> 8) & 0xFF), (len(value) & 0xFF)])
        data.extend(value)
        self.results.extend(data)

    def get(self, **kwargs):
        return self.results


class UnifiTLV(TLV):

    def get(self, version, command):
        value = bytearray([version, command, 0, len(self.results)])
        value.extend(self.results)

        return value

def getuptime():

    tmp = uptime()
    if tmp is None and psutil.FREEBSD :
        boottime = "0"
        matches = ""
        boottime = get_single_sysctl("kern.boottime")
        matches = re.search("sec = (\d+)", boottime)
        if matches :
	        boottime = matches.group(1)
        if int(boottime) == 0 :
            return 0
        tmp = time.time() - int(boottime)
    return 0 if tmp is None else int(tmp)

def escapeshellarg(arg):
    return "\\'".join("'" + p + "'" for p in arg.split("'"))

def get_sysctl(names) :
    import subprocess

    if (names is None):
        return dict()
    if isinstance(names, list) : 
		name_list = [escapeshellarg(val) for val in names]
    else: 
	    name_list = [escapeshellarg(names)]
	
    output = subprocess.check_output("/sbin/sysctl -iq "+" ".join(name_list), shell=True)
    values = dict()
    for line in output.split("\n"):
        print(line)
        line = line.split(":",1)
        if (len(line) == 2) :
            print(line[0])
            print(line[1])
            values[line[0]] = line[1]
            

	return values

def get_single_sysctl(name):
	if (name is None or name ==''): 
		return ""
	value = get_sysctl(name)
	if (value is None or value =='' or name not in value): 
		return ""
	return value[name]


def mac_string_2_array(mac):
    return [int(i, 16) for i in mac.replace('-',':').split(':')]


def ip_string_2_array(mac):
    return [int(i) for i in mac.split('.')]

def ping(host,iface):
    """
    Returns True if host responds to a ping request
    """
    import subprocess, platform

    # Ping parameters as function of OS
    ping_str = "-n 1 " if  platform.system().lower()=="windows" else ("-c 1 " + (" -I {}".format(iface) if iface is not None else ""))
    args = "ping " + " " + ping_str + " " + host
    need_sh = False if  platform.system().lower()=="windows" else True

    # Ping
    return subprocess.call(args, shell=need_sh) == 0

def get_ipv4addr(if_addrs,lan_if):
    if if_addrs.has_key(lan_if):
        addr = if_addrs[lan_if]
        tmp = [mac for mac in addr if mac.family == 2]
        if(len(tmp)>0):
            return tmp[0]
    return None
def get_macaddr(if_addrs,lan_if):
    if if_addrs.has_key(lan_if):
        addr = if_addrs[lan_if]
        tmp = [mac for mac in addr if mac.family == -1 or mac.family==18]
        if(len(tmp)>0):
            return tmp[0]
    return None
def get_apv6addr(if_addrs,lan_if):
    if if_addrs.has_key(lan_if):
        addr = if_addrs[lan_if]
        tmp = [mac for mac in addr if mac.family == 23]
        if(len(tmp)>0):
            return tmp[0]
    return None

def _byteify(data, ignore_dicts = False):
    # if this is a unicode string, return its string representation
    if isinstance(data, unicode):
        return data.encode('utf-8')
    # if this is a list of values, return list of byteified values
    if isinstance(data, list):
        return [ _byteify(item, ignore_dicts=True) for item in data ]
    # if this is a dictionary, return dictionary of byteified keys and values
    # but only if we haven't already byteified it
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.iteritems()
        }
    # if it's anything else, return it in its original form
    return data


def get_dpinger_status(gwname, detailed = False) :
    running_processes = running_dpinger_processes()
    if not running_processes.has_key(gwname) : 
        return None

    proc = running_processes[gwname]
    del running_processes

    timeoutcounter = 0
    while True:
        if (not os.path.exists(proc['socket'])) :
            log_error("dpinger: status socket {} not found".format(proc['socket']))
            return None
        
        conn = stream_socket_client(proc['socket'])
        if (not conn) :
            log_error('dpinger: cannot connect to status socket %1$s - %2$s (%3$s)'.format(proc['socket'], errstr, errno))
            return None
        

        status = '';
        while True:
            data = conn.recv(1024)
            if not data: break
            status+=data
        conn.close()
        print status
        break

        

# 		r = {};
# 		list(
# 			$r['gwname'],
# 			$r['latency_avg'],
# 			$r['latency_stddev'],
# 			$r['loss']
# 		) = explode(' ', preg_replace('/\n/', '', $status));

# 		// dpinger returns '<gwname> 0 0 0' when queried directly after it starts.
# 		// while a latency of 0 and a loss of 0 would be perfect, in a real world it doesnt happen.
# 		// or does it, anyone? if so we must 'detect' the initialization period differently..
# 		$ready = $r['latency_stddev'] != '0' || $r['loss'] != '0';

# 		if ($ready) {
# 			break;
# 		} else {
# 			$timeoutcounter++;
# 			if ($timeoutcounter > 300) {
# 				log_error(sprintf(gettext('dpinger: timeout while retrieving status for gateway %s'), $gwname));
# 				return false;
# 			}
# 			usleep(10000);
# 		}
# 	}

# 	$r['srcip'] = $proc['srcip'];
# 	$r['targetip'] = $proc['targetip'];

# 	$gateways_arr = return_gateways_array();
# 	unset($gw);
# 	if (isset($gateways_arr[$gwname])) {
# 		$gw = $gateways_arr[$gwname];
# 	}

# 	$r['latency_avg'] = round($r['latency_avg']/1000, 3);
# 	$r['latency_stddev'] = round($r['latency_stddev']/1000, 3);

# 	$r['status'] = "none";
# 	if (isset($gw) && isset($gw['force_down'])) {
# 		$r['status'] = "force_down";
# 	} else if (isset($gw)) {
# 		$settings = return_dpinger_defaults();

# 		$keys = array(
# 		    'latencylow',
# 		    'latencyhigh',
# 		    'losslow',
# 		    'losshigh'
# 		);

# 		/* Replace default values by user-defined */
# 		foreach ($keys as $key) {
# 			if (isset($gw[$key]) && is_numeric($gw[$key])) {
# 				$settings[$key] = $gw[$key];
# 			}
# 		}

# 		if ($r['latency_avg'] > $settings['latencyhigh']) {
# 			if ($detailed) {
# 				$r['status'] = "highdelay";
# 			} else {
# 				$r['status'] = "down";
# 			}
# 		} else if ($r['loss'] > $settings['losshigh']) {
# 			if ($detailed) {
# 				$r['status'] = "highloss";
# 			} else {
# 				$r['status'] = "down";
# 			}
# 		} else if ($r['latency_avg'] > $settings['latencylow']) {
# 			$r['status'] = "delay";
# 		} else if ($r['loss'] > $settings['losslow']) {
# 			$r['status'] = "loss";
# 		}
# 	}

# 	return $r;
# }

def running_dpinger_processes():
    import glob

    pidfiles = glob.glob("{}/dpinger_*.pid".format(g['varrun_path']))
    result = {}
    if len(pidfiles) == 0:
        return result
    for pidfile in pidfiles:
        print (os.path.basename(pidfile))    
        match = re.search("^dpinger_(.+)~([^~]+)~([^~]+)\.pid$", os.path.basename(pidfile))
        if match :
            socket_file = re.sub('\.pid$', '.sock',pidfile)
            result[match.group(1)]={
                'srcip'    : match.group(2),
                'targetip' : match.group(3),
                'pidfile'  : pidfile,
                'socket'   : socket_file
            }
    return result


#  def return_gateways_status(byname = False) {

#  	dpinger_gws = running_dpinger_processes()
#  	status = {}

# 	$gateways_arr = return_gateways_array();

# 	foreach ($dpinger_gws as $gwname , $gwdata) {
# 		// If action is disabled for this gateway, then we want a detailed status.
# 		// That reports "highdelay" or "highloss" rather than just "down".
# 		// Because reporting the gateway down would be misleading (gateway action is disabled)
# 		$detailed = $gateways_arr[$gwname]['action_disable'];
# 		$dpinger_status = get_dpinger_status($gwname, $detailed);
# 		if ($dpinger_status === false) {
# 			continue;
# 		}

# 		if ($byname == false) {
# 			$target = $dpinger_status['targetip'];
# 		} else {
# 			$target = $gwname;
# 		}

# 		$status[$target] = array();
# 		$status[$target]['monitorip'] = $dpinger_status['targetip'];
# 		$status[$target]['srcip'] = $dpinger_status['srcip'];
# 		$status[$target]['name'] = $gwname;
# 		$status[$target]['delay'] = empty($dpinger_status['latency_avg']) ? "0ms" : $dpinger_status['latency_avg'] . "ms";
# 		$status[$target]['stddev'] = empty($dpinger_status['latency_stddev']) ? "0ms" : $dpinger_status['latency_stddev'] . "ms";
# 		$status[$target]['loss'] = empty($dpinger_status['loss']) ? "0.0%" : round($dpinger_status['loss'], 1) . "%";
# 		$status[$target]['status'] = $dpinger_status['status'];
# 	}

# 	/* tack on any gateways that have monitoring disabled
# 	 * or are down, which could cause gateway groups to fail */
# 	$gateways_arr = return_gateways_array();
# 	foreach ($gateways_arr as $gwitem) {
# 		if (!isset($gwitem['monitor_disable'])) {
# 			continue;
# 		}
# 		if (!is_ipaddr($gwitem['monitor'])) {
# 			$realif = $gwitem['interface'];
# 			$tgtip = get_interface_gateway($realif);
# 			if (!is_ipaddr($tgtip)) {
# 				$tgtip = "none";
# 			}
# 			$srcip = find_interface_ip($realif);
# 		} else {
# 			$tgtip = $gwitem['monitor'];
# 			$srcip = find_interface_ip($realif);
# 		}
# 		if ($byname == true) {
# 			$target = $gwitem['name'];
# 		} else {
# 			$target = $tgtip;
# 		}

# 		/* failsafe for down interfaces */
# 		if ($target == "none") {
# 			$target = $gwitem['name'];
# 			$status[$target]['name'] = $gwitem['name'];
# 			$status[$target]['delay'] = "0.0ms";
# 			$status[$target]['loss'] = "100.0%";
# 			$status[$target]['status'] = "down";
# 		} else {
# 			$status[$target]['monitorip'] = $tgtip;
# 			$status[$target]['srcip'] = $srcip;
# 			$status[$target]['name'] = $gwitem['name'];
# 			$status[$target]['delay'] = "";
# 			$status[$target]['loss'] = "";
# 			$status[$target]['status'] = "none";
# 		}

# 		$status[$target]['monitor_disable'] = true;
# 	}
# 	return($status);
# }
def log_error(message):
    import logging
    logging.error(message)

def stream_socket_client(path):
    import socket,os
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    return s
