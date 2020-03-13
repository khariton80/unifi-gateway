
dirs = ntop.getDirs()
package.path = dirs.installdir .. "/scripts/lua/modules/?.lua;" .. package.path

require "lua_utils"
local json = require ("dkjson")

ret = {}
interfaces = interface.getIfNames()
for k,v in pairs(interfaces) do
   if_name = getInterfaceName(k)
   interface.select(if_name)
   hosts_stats = interface.getHostsInfo()
   hosts_stats = hosts_stats["hosts"]
   for k1,v1 in pairs(hosts_stats) do
      if(((v1["localhost"] == true) and (v1["ip"] ~= nil))) then
         host = interface.getHostInfo(v1["ip"], nil)
         ret[v1["ip"]] = host
      end
   end
   end
   sendHTTPHeader('application/json')
   print (json.encode(ret, nil) )

