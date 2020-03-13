# coding: utf-8
from uptime import uptime
import time
import re
import psutil
import ctypes
import struct
import os
import xmltodict
import urllib2
global pfsense_const
pfsense_const = {
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

global _config
#pfsense_const['cf_conf_path']='conf'
with open(pfsense_const['cf_conf_path']+'/config.xml') as fd:
        _config = xmltodict.parse(fd.read())["pfsense"]

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
        line = line.split(":",1)
        if (len(line) == 2) :
            values[line[0]] = line[1]
            

	return values

def get_single_sysctl(name):
	if (name is None or name =='' or not psutil.FREEBSD): 
		return ""
	value = get_sysctl(name)
	if (value is None or value =='' or name not in value): 
		return ""
	return value[name]

def get_dpinger_status(gwname) :
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
        status = ''
        while True:
            data = conn.recv(1024)
            if not data: break
            status+=data
        conn.close()
        
        r = {}
        tmp =status.replace('\n', '').split(' ')
        r['gwname']  = tmp[0] if len(tmp)>0 else ""
        r['latency_avg']  = float(tmp[1]) if len(tmp)>1 else 0.0
        r['latency_stddev']  = float(tmp[2]) if len(tmp)>2 else 0.0
        r['loss']  = float(tmp[3]) if len(tmp)>3 else 0.0

        ready = r['latency_stddev'] != 0 or r['loss'] != 0

        if (ready): 
            break
        else :
            timeoutcounter+=1
            if (timeoutcounter > 300):
                log_error('dpinger: timeout while retrieving status for gateway %s'.format(gwname))
                return None
            time.sleep(1000)
    r['srcip'] = proc['srcip']
    r['targetip'] = proc['targetip']
    r['latency_avg'] = r['latency_avg']/1000+1
    r['latency_stddev'] = r['latency_stddev']/1000+1

    return r

def running_dpinger_processes():
    import glob

    pidfiles = glob.glob("{}/dpinger_*.pid".format(pfsense_const['varrun_path']))
    result = {}
    if len(pidfiles) == 0:
        return result
    for pidfile in pidfiles:
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
def get_dns_servers():
    dns_servers = []
    dns_s=None
    if (os.path.exists("/etc/resolv.conf")):
        dns_s = file_get_contents("/etc/resolv.conf").splitlines()
    if dns_s and len (dns_s)>0:
        for dns in dns_s:
            matches = re.search("nameserver (.*)",dns)
            if (matches):
                dns_servers.append(matches.group(1))
    return dns_servers



def getGatewaysPingerStatus():
    result ={}
    for gateway in _config["gateways"]["gateway_item"]:
        tmp = get_dpinger_status(gateway['name'])
        ifname = _config['interfaces'][gateway['interface']]["if"] 
        if tmp is not None :
            if (os.path.exists("{}/{}_router".format(pfsense_const['tmp_path'],ifname))): 
                gw = file_get_contents("{}/{}_router".format(pfsense_const['tmp_path'],ifname)).strip(" \n")
                tmp['gateway']=gw

            result[ifname]=tmp
    return result
def is_ipaddrv4(ipaddr): 
    return True
#     if (!is_string($ipaddr) || empty($ipaddr) || ip2long($ipaddr) === FALSE) {
#     return false;
#     }
#     return true;
# }

# def get_interface_gateway(interface) :
#      dynamic = False

#     if (substr(interface, 0, 4) == '_vip') :
#         interface = get_configured_vip_interface(interface)
#         if (substr(interface, 0, 4) == '_vip') :
#             interface = get_configured_vip_interface(interface)

#     gw = None
#     gwcfg = _config['interfaces'][interface]
#     if (gwcfg['gateway'] is not None and len(_config['gateways']['gateway_item']>0)):
#         for gateway in _config['gateways']['gateway_item']:
#             if ((gateway['name'] == gwcfg['gateway']) and (is_ipaddrv4(gateway['gateway']))):
#                 gw = gateway['gateway']
#                 break

#     # for dynamic interfaces we handle them through the $interface_router file.
#     if ((gw is None or not is_ipaddrv4(gw)) and not is_ipaddrv4(gwcfg['ipaddr'])): 
#         realif = get_real_interface(interface)
#         if (os.path.exists("{}/{}_router".format(pfsense_const['tmp_path'],realif))): 
#             gw = file_get_contents("{}/{}_router".format(pfsense_const['tmp_path'],realif)).strip(" \n")
#             dynamic = True
#         if (os.path.exists("{}/{}_defaultgw".format(pfsense_const['tmp_path'],realif))):
#             dynamic = "default"
#     return gw,dynamic
# }
def pfSense_interface_listget():
    pass
def get_interface_arr(flush = False):
    global interface_arr_cache
    #/* If the cache doesn't exist, build it */
    if (interface_arr_cache is None  or flush):
        interface_arr_cache = pfSense_interface_listget()
    return interface_arr_cache

# def return_gateways_array(disabled = False, localhost = False, inactive = False, integer_index = False) {
# 	global $config, $g;

# 	$gateways_arr = array();
# 	$gateways_arr_temp = array();
# 	$cgw4 = getcurrentdefaultgatewayip('inet');
# 	$cgw6 = getcurrentdefaultgatewayip('inet6');
# 	$found_defaultv4 = 0;
# 	$found_defaultv6 = 0;

# 	// Ensure the interface cache is up to date first
# 	$interfaces = get_interface_arr(true);

# 	$i = -1;
# 	/* Process/add all the configured gateways. */
# 	if (is_array($config['gateways']['gateway_item'])) {
# 		foreach ($config['gateways']['gateway_item'] as $gateway) {
# 			/* Increment it here to do not skip items */
# 			$i++;
# 			unset($gateway['defaultgw']);

# 			if (empty($config['interfaces'][$gateway['interface']])) {
# 				if ($inactive === false) {
# 					continue;
# 				} else {
# 					$gateway['inactive'] = true;
# 				}
# 			}
# 			$wancfg = $config['interfaces'][$gateway['interface']];

# 			/* skip disabled interfaces */
# 			if ($disabled === false && (!isset($wancfg['enable']))) {
# 				continue;
# 			}

# 			/* if the gateway is dynamic and we can find the IPv4, Great! */
# 			if (empty($gateway['gateway']) || $gateway['gateway'] == "dynamic") {
# 				if ($gateway['ipprotocol'] == "inet") {
# 					/* we know which interfaces is dynamic, this should be made a function */
# 					$gateway['gateway'] = get_interface_gateway($gateway['interface']);
# 					/* no IP address found, set to dynamic */
# 					if (!is_ipaddrv4($gateway['gateway'])) {
# 						$gateway['gateway'] = "dynamic";
# 					}
# 					$gateway['dynamic'] = true;
# 				}

# 				/* if the gateway is dynamic and we can find the IPv6, Great! */
# 				else if ($gateway['ipprotocol'] == "inet6") {
# 					/* we know which interfaces is dynamic, this should be made a function, and for v6 too */
# 					$gateway['gateway'] = get_interface_gateway_v6($gateway['interface']);
# 					/* no IPv6 address found, set to dynamic */
# 					if (!is_ipaddrv6($gateway['gateway'])) {
# 						$gateway['gateway'] = "dynamic";
# 					}
# 					$gateway['dynamic'] = true;
# 				}
# 			} else {
# 				/* getting this detection right is hard at this point because we still don't
# 				 * store the address family in the gateway item */
# 				if (is_ipaddrv4($gateway['gateway'])) {
# 					$gateway['ipprotocol'] = "inet";
# 				} else if (is_ipaddrv6($gateway['gateway'])) {
# 					$gateway['ipprotocol'] = "inet6";
# 				}
# 			}

# 			if (isset($gateway['monitor_disable'])) {
# 				$gateway['monitor_disable'] = true;
# 			} else if (empty($gateway['monitor'])) {
# 				$gateway['monitor'] = $gateway['gateway'];
# 			}

# 			if (isset($gateway['action_disable'])) {
# 				$gateway['action_disable'] = true;
# 			}

# 			$gateway['friendlyiface'] = $gateway['interface'];

# 			/* special treatment for tunnel interfaces */
# 			if ($gateway['ipprotocol'] == "inet6") {
# 				$gateway['interface'] = get_real_interface($gateway['interface'], "inet6", false, false);
# 			} else {
# 				$gateway['interface'] = get_real_interface($gateway['interface'], "inet", false, false);
# 			}

# 			if ($gateway['ipprotocol'] == "inet" && 
# 					($config['gateways']['defaultgw4'] == $gateway['name'] || $gateway['gateway'] == $cgw4)) {
# 				$gateway['isdefaultgw'] = true;
# 				$found_defaultv4 = 1;
# 			} else if ($gateway['ipprotocol'] == "inet6" && 
# 					($config['gateways']['defaultgw6'] == $gateway['name'] || $gateway['gateway'] == $cgw6)) {
# 				$gateway['isdefaultgw'] = true;
# 				$found_defaultv6 = 1;
# 			}
# 			/* include the gateway index as the attribute */
# 			$gateway['attribute'] = $i;

# 			/* Remember all the gateway names, even ones to be skipped because they are disabled. */
# 			/* Then we can easily know and match them later when attempting to add dynamic gateways to the list. */
# 			$gateways_arr_temp[$gateway['name']] = $gateway;

# 			/* skip disabled gateways if the caller has not asked for them to be returned. */
# 			if (!($disabled === false && isset($gateway['disabled']))) {
# 				$gateways_arr[$gateway['name']] = $gateway;
# 			}
# 		}
# 	}
# 	unset($gateway);

# 	//Sort the array by GW name before moving on.
# 	ksort($gateways_arr, SORT_STRING | SORT_FLAG_CASE);

# 	/* Loop through all interfaces with a gateway and add it to a array */
# 	if ($disabled == false) {
# 		$iflist = get_configured_interface_with_descr();
# 	} else {
# 		$iflist = get_configured_interface_with_descr(true);
# 	}

# 	/* Process/add dynamic v4 gateways. */
# 	foreach ($iflist as $ifname => $friendly) {
# 		if (!interface_has_gateway($ifname)) {
# 			continue;
# 		}

# 		if (empty($config['interfaces'][$ifname])) {
# 			continue;
# 		}

# 		$ifcfg = &$config['interfaces'][$ifname];
# 		if (!isset($ifcfg['enable'])) {
# 			continue;
# 		}

# 		if (!empty($ifcfg['ipaddr']) && is_ipaddrv4($ifcfg['ipaddr'])) {
# 			continue;
# 		}

# 		$ctype = "";
# 		switch ($ifcfg['ipaddr']) {
# 			case "dhcp":
# 			case "pppoe":
# 			case "l2tp":
# 			case "pptp":
# 			case "ppp":
# 				$ctype = strtoupper($ifcfg['ipaddr']);
# 				break;
# 			default:
# 				$tunnelif = substr($ifcfg['if'], 0, 3);
# 				if (substr($ifcfg['if'], 0, 4) == "ovpn") {
# 					switch (substr($ifcfg['if'], 4, 1)) {
# 						case "c":
# 							$ovpntype = "openvpn-client";
# 							break;
# 						case "s":
# 							$ovpntype = "openvpn-server";
# 							break;
# 						default:
# 							// unknown ovpn type
# 							continue 2;
# 					}
# 					$ovpnid = substr($ifcfg['if'], 5);
# 					if (is_array($config['openvpn'][$ovpntype])) {
# 						foreach ($config['openvpn'][$ovpntype] as & $ovpnconf) {
# 							if ($ovpnconf['vpnid'] == $ovpnid) {
# 								// skip IPv6-only interfaces
# 								if ($ovpnconf['create_gw'] == "v6only") {
# 									continue 3;
# 								}
# 								// skip tap interfaces
# 								if ($ovpnconf['dev_mode'] == "tap") {
# 									continue 3;
# 								}
# 							}
# 						}
# 					}
# 					$ctype = "VPNv4";
# 				} else if ($tunnelif == "gif" || $tunnelif == "gre") {
# 					$ctype = "TUNNELv4";
# 				}
# 				break;
# 		}
# 		$ctype = "_". strtoupper($ctype);

# 		$gateway = array();
# 		$gateway['dynamic'] = false;
# 		$gateway['ipprotocol'] = "inet";
# 		$gateway['gateway'] = get_interface_gateway($ifname, $gateway['dynamic']);
# 		$gateway['interface'] = get_real_interface($ifname);
# 		$gateway['friendlyiface'] = $ifname;
# 		$gateway['name'] = "{$friendly}{$ctype}";
# 		$gateway['attribute'] = "system";

# 		if (($gateway['dynamic'] === "default") && ($found_defaultv4 == 0)) {
# 			$gateway['isdefaultgw'] = true;
# 			$gateway['dynamic'] = true;
# 			$found_defaultv4 = 1;
# 		}

# 		/* Loopback dummy for dynamic interfaces without a IP */
# 		if (!is_ipaddrv4($gateway['gateway']) && $gateway['dynamic'] == true) {
# 			$gateway['gateway'] = "dynamic";
# 		}

# 		/* automatically skip known static and dynamic gateways that were previously processed */
# 		foreach ($gateways_arr_temp as $gateway_item) {
# 			if ((($ifname == $gateway_item['friendlyiface'] && $friendly == $gateway_item['name'])&& ($gateway['ipprotocol'] == $gateway_item['ipprotocol'])) ||
# 			    (($ifname == $gateway_item['friendlyiface'] && $gateway_item['dynamic'] == true) && ($gateway['ipprotocol'] == $gateway_item['ipprotocol']))) {
# 				continue 2;
# 			}
# 		}

# 		if (is_ipaddrv4($gateway['gateway'])) {
# 			$gateway['monitor'] = $gateway['gateway'];
# 		}

# 		$gateway['descr'] = "Interface {$friendly}{$ctype} Gateway";
# 		$gateways_arr[$gateway['name']] = $gateway;
# 	}
# 	unset($gateway);

# 	/* Process/add dynamic v6 gateways. */
# 	foreach ($iflist as $ifname => $friendly) {
# 		/* If the user has disabled IPv6, they probably don't want any IPv6 gateways. */
# 		if (!isset($config['system']['ipv6allow'])) {
# 			break;
# 		}

# 		if (!interface_has_gatewayv6($ifname)) {
# 			continue;
# 		}

# 		if (empty($config['interfaces'][$ifname])) {
# 			continue;
# 		}

# 		$ifcfg = &$config['interfaces'][$ifname];
# 		if (!isset($ifcfg['enable'])) {
# 			continue;
# 		}

# 		if (!empty($ifcfg['ipaddrv6']) && is_ipaddrv6($ifcfg['ipaddrv6'])) {
# 			continue;
# 		}

# 		$ctype = "";
# 		switch ($ifcfg['ipaddrv6']) {
# 			case "slaac":
# 			case "dhcp6":
# 			case "6to4":
# 			case "6rd":
# 				$ctype = strtoupper($ifcfg['ipaddrv6']);
# 				break;
# 			default:
# 				$tunnelif = substr($ifcfg['if'], 0, 3);
# 				if (substr($ifcfg['if'], 0, 4) == "ovpn") {
# 					switch (substr($ifcfg['if'], 4, 1)) {
# 						case "c":
# 							$ovpntype = "openvpn-client";
# 							break;
# 						case "s":
# 							$ovpntype = "openvpn-server";
# 							break;
# 						default:
# 							// unknown ovpn type
# 							continue 2;
# 					}
# 					$ovpnid = substr($ifcfg['if'], 5);
# 					if (is_array($config['openvpn'][$ovpntype])) {
# 						foreach ($config['openvpn'][$ovpntype] as & $ovpnconf) {
# 							if ($ovpnconf['vpnid'] == $ovpnid) {
# 								// skip IPv4-only interfaces
# 								if ($ovpnconf['create_gw'] == "v4only") {
# 									continue 3;
# 								}
# 								// skip tap interfaces
# 								if ($ovpnconf['dev_mode'] == "tap") {
# 									continue 3;
# 								}
# 							}
# 						}
# 					}
# 					$ctype = "VPNv6";
# 				} else if ($tunnelif == "gif" || $tunnelif == "gre") {
# 					$ctype = "TUNNELv6";
# 				}
# 				break;
# 		}
# 		$ctype = "_". strtoupper($ctype);

# 		$gateway = array();
# 		$gateway['dynamic'] = false;
# 		$gateway['ipprotocol'] = "inet6";
# 		$gateway['gateway'] = get_interface_gateway_v6($ifname, $gateway['dynamic']);
# 		$gateway['interface'] = get_real_interface($ifname, "inet6");
# 		switch ($ifcfg['ipaddrv6']) {
# 			case "6rd":
# 			case "6to4":
# 				$gateway['dynamic'] = "default";
# 				break;
# 		}
# 		$gateway['friendlyiface'] = $ifname;
# 		$gateway['name'] = "{$friendly}{$ctype}";
# 		$gateway['attribute'] = "system";

# 		if (($gateway['dynamic'] === "default") && ($found_defaultv6 == 0)) {
# 			$gateway['isdefaultgw'] = true;
# 			$gateway['dynamic'] = true;
# 			$found_defaultv6 = 1;
# 		}

# 		/* Loopback dummy for dynamic interfaces without a IP */
# 		if (!is_ipaddrv6($gateway['gateway']) && $gateway['dynamic'] == true) {
# 			$gateway['gateway'] = "dynamic";
# 		}

# 		/* automatically skip known static and dynamic gateways that were previously processed */
# 		foreach ($gateways_arr_temp as $gateway_item) {
# 			if ((($ifname == $gateway_item['friendlyiface'] && $friendly == $gateway_item['name']) && ($gateway['ipprotocol'] == $gateway_item['ipprotocol'])) ||
# 			    (($ifname == $gateway_item['friendlyiface'] && $gateway_item['dynamic'] == true) && ($gateway['ipprotocol'] == $gateway_item['ipprotocol']))) {
# 				continue 2;
# 			}
# 		}

# 		if (is_ipaddrv6($gateway['gateway'])) {
# 			$gateway['monitor'] = $gateway['gateway'];
# 		}

# 		$gateway['descr'] = "Interface {$friendly}{$ctype} Gateway";
# 		$gateways_arr[$gateway['name']] = $gateway;
# 	}
# 	unset($gateway);

# 	/* FIXME: Should this be enabled.
# 	 * Some interface like wan might be default but have no info recorded
# 	 * the config. */
# 	/* this is a fallback if all else fails and we want to get packets out @smos */
# 	if ($found_defaultv4 == 0 || $found_defaultv6 == 0) {
# 		foreach ($gateways_arr as &$gateway) {
# 			if (($gateway['friendlyiface'] == "wan") && ($found_defaultv4 == 0) && (!isset($gateway['ipprotocol']) || ($gateway['ipprotocol'] == "inet"))) {
# 				if (file_exists("{$g['tmp_path']}/{$gateway['interface']}_defaultgw")) {
# 					$gateway['isdefaultgw'] = true;
# 					$found_defaultv4 = 1;
# 				}
# 			}
# 			else if (($gateway['friendlyiface'] == "wan") && ($found_defaultv6 == 0) && ($gateway['ipprotocol'] == "inet6")) {
# 				if (file_exists("{$g['tmp_path']}/{$gateway['interface']}_defaultgwv6")) {
# 					$gateway['isdefaultgw'] = true;
# 					$found_defaultv6 = 1;
# 				}
# 			}
# 		}
# 	}

# 	if ($localhost === true) {
# 		/* attach localhost for Null routes */
# 		$gwlo4 = array();
# 		$gwlo4['name'] = "Null4";
# 		$gwlo4['interface'] = "lo0";
# 		$gwlo4['ipprotocol'] = "inet";
# 		$gwlo4['gateway'] = "127.0.0.1";
# 		$gwlo6 = array();
# 		$gwlo6['name'] = "Null6";
# 		$gwlo6['interface'] = "lo0";
# 		$gwlo6['ipprotocol'] = "inet6";
# 		$gwlo6['gateway'] = "::1";
# 		$gateways_arr['Null4'] = $gwlo4;
# 		$gateways_arr['Null6'] = $gwlo6;
# 	}

# 	if ($integer_index) {
# 		$gateways_arr = array_values($gateways_arr);
# 	}

# 	if ($found_defaultv4 != 1 && is_ipaddr($cgw4)) {
# 		foreach($gateways_arr as &$gw) {
# 			if ($gw['gateway'] == $cgw4) {
# 				$gw['isdefaultgw'] = true;
# 			}
# 		}
# 	}
# 	if ($found_defaultv6 != 1 && is_ipaddr($cgw6)) {
# 		foreach($gateways_arr as &$gw) {
# 			if ($gw['gateway'] == $cgw6) {
# 				$gw['isdefaultgw'] = true;
# 			}
# 		}
# 	}
# 	return($gateways_arr);
# }
def get_temp() :
    temp_out = get_single_sysctl("dev.cpu.0.temperature")
    if (temp_out == "") :
        temp_out = get_single_sysctl("hw.acpi.thermal.tz0.temperature")
    temp_out = temp_out.strip('C').strip(' ')
    if (temp_out=="" or temp_out[0] == '-'):
        return '0'
    return temp_out

def log_error(message):
    import logging
    logging.error(message)

def get_ntopng_stats(login, password,host):
    import ssl
    url = "{}:3000/lua/unifi_get_statistics.lua".format(host)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        headers = {
            'Cookie': 'user={}; password={}'.format(login,password),
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36'
        }
        request = urllib2.Request(url, None, headers)
        response = urllib2.urlopen(request, context=ctx)
        result = response.read()
        return result
    except Exception as ex:
        log_error(ex)
        return None


def stream_socket_client(path):
    import socket,os
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    return s
def file_get_contents(path):
    with open(path, 'r') as content_file:
        content = content_file.read()
    return content
