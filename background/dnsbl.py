from analysis_base import AnalysisBase

import config
import common
import struct
import socket
import os
import dns.resolver

class DNSblack(AnalysisBase):
	def __init__(self, flowbackend, databackend):
		AnalysisBase.__init__(self, flowbackend, databackend)

	
	def analyze(self, startBucket, endBucket):

		def int_to_dotted(ipint):
			ip = ""
			for i in range(4):
				ip1 = ""
				for j in range(8):
					ip1=str(ipint % 2)+ip1
					ipint = ipint >> 1
				ip = str(int(ip1,2)) + "." + ip
			return ip.strip(".")


		def dotted_to_int(dotted):

			return reduce(lambda x,y: (x << 8) + y, [ int(x) for x in dotted.split('.') ])


		def getDNSBL(path, index):

			ips = []

			# testvlues for comparison		
			#ips.append(2192532937)
			#ips.append(2192729352)
			#print int_to_dotted(2192729352)

			dnsblist = open(path)

			for line in dnsblist:
				string_ip = line.split()[index]
				#print string_ip
				#print dotted_to_int(string_ip)
				ips.append(dotted_to_int(string_ip))

			dnsblist.close()
			
			return ips

		def getDNSBLNetwork(path, index):

			net = []

			dnsblist = open(path)

			for line in dnsblist:
				string_net = line.split()[index]
				(network, mask) = string_net.split("/")
				net.append((network, mask))

			dnsblist.close()
			
			return net

		def prepareNet(net):
			
			lst = []

			for (network, mask) in net:
				#prep_net = dotted_to_int(network) & (pow(2, 32) - pow(2, int(mask)) - 1)
				prep_net = dotted_to_int(network)
				lst.append((prep_net, mask))
			
			return lst

		def checkNetMember(ip, lst):
			
			#print "check ip: " + int_to_dotted(ip & 0x00000000FFFFFFFF)
			#for k in lists.keys():
			for (prep_net, mask) in lst:
				ip_network_part = ip & (pow(2, 32) - (pow(2, 32 - int(mask)) ))
				#ip_network_part = ip >> (32 - int(mask))
				#print "nwpart: " + int_to_dotted(ip_network_part)
				#print "comp: " + int_to_dotted(ip_network_part & 0x00000000FFFFFFFF) +" --- " + int_to_dotted(prep_net & 0x00000000FFFFFFFF) + "ip " + int_to_dotted(ip & 0x00000000FFFFFFFF)
				#print "vals: " + str(ip_network_part & 0x00000000FFFFFFFF) + "-----" + str(int(prep_net & 0x00000000FFFFFFFF))
				if((ip_network_part & 0x00000000FFFFFFFF) == (prep_net & 0x00000000FFFFFFFF)):
					print "FOUND"
					print int_to_dotted(ip_network_part)
					print int_to_dotted(ip)
					return True
				else:
					return False
		


		def getRecord(string_ip, nameservers, bl_address): 

			ip = string_ip.split(".")
			ip.reverse()
			#print ip
			
			rev_ip = str(ip[0]) + "." + str(ip[1]) + "." + str(ip[2]) + "." + str(ip[3])
			#print rev_ip

			try:
				res = dns.resolver.Resolver(configure=False)
				res.nameservers = nameservers		
				answers = res.query(rev_ip + "." + bl_address)
				for data in answers:
					#print data
					if(data != "127.0.0.2"):
						print str(string_ip) + " in blacklist (answer: " + str(data) + ")"
						return True
				return False
			except:
				#print "cannot find record"
				return False


		tableName = common.DB_FLOW_PREFIX + str(config.flow_bucket_sizes[0])

		dnsservers = ["131.159.14.206"]
		offline = False
		offline_network = False
		bl_files = {"nix" : ("/home/simon/daten/dnsbl/nixspam-ip.dump", 1), "psbl" : ("/home/simon/daten/dnsbl/psbl.txt", 0)}
		bl_lists = {}
		bl_network_files = {"drop-spamhaus" : ("/home/simon/daten/dnsbl/drop-spamhaus.txt", 0), "test" : ("/home/simon/daten/dnsbl/testnet", 0), "test2" : ("/home/simon/daten/dnsbl/testnet2", 0)}
		#bl_network_files = {"test" : ("/home/simon/daten/dnsbl/testnet", 0)}
		bl_network_lists = {}
		bl_network_lists_prep = {}
		online = False
		bl_address = ["pbl.spamhaus.org", "zen.spamhaus.org", "sbl.spamhaus.org,", "xbl.spamhaus.org"]

		query = False
		aggregate = True

		if(offline):
			for lst in bl_files.keys():
				(path, index) = bl_files[lst]
				ips = getDNSBL(path, index)
				bl_lists.update({lst : ips})

				#print ips
			#print bl_lists

		if(offline_network):
			#print "do offline network"

			for lst in bl_network_files.keys():
				(path, index) = bl_network_files[lst]
				net = getDNSBLNetwork(path, index)
				bl_network_lists.update({lst : net})

			for i in bl_network_lists.keys():
				#print bl_network_lists[i]
				
				bl_network_lists_prep.update({i : prepareNet(bl_network_lists[i])})
				
			#print bl_network_lists_prep
			
		res_source = self.flowBackend.run_query(tableName, "SELECT sourceIPv4Address, COUNT(sourceIPv4Address) AS count FROM %s WHERE bucket = " + str(startBucket) + " GROUP BY sourceIPv4Address")

		#print res_source

		for ele in res_source:

			if(offline_network):

				sip = ele["sourceIPv4Address"]
				count = ele["count"]


				for k in bl_network_lists_prep.keys():
					
					if(checkNetMember(sip, bl_network_lists_prep[k])):
						print "match"
						self.dataBackend.insert("blacklist_badhosts", {"bucket" : startBucket, "blacklist" : k, "black_host" : int(sip), "black_host_string" : int_to_dotted(sip), "count" : int(count)})
	
					
			
			if(offline):

				for l in bl_lists.keys():

					ips = bl_lists[l]
					
					# doesn't work - don't know why
					#print socket.inet_ntoa(ele["sourceIPv4Address"])

					# use this instead, if needed 
					#print int_to_dotted(ele["sourceIPv4Address"])

					sip = ele["sourceIPv4Address"]
					count = ele["count"]
			
					for comp in ips:
						#print "comparing " + str(comp) + " with " + str(sip)
					
						if(comp == sip):
							print "match: comparing " + str(comp) + " with " + str(sip)
							self.dataBackend.insert("blacklist_badhosts", {"bucket" : startBucket, "blacklist" : l, "black_host" : sip, "black_host_string" : int_to_dotted(sip), "count" : count})
	
			if(online):
				string_ip = int_to_dotted(ele["sourceIPv4Address"])
				count = ele["count"]

				for bl_adr in bl_address:
					blacklisted = (getRecord(string_ip, dnsservers, bl_adr))
				
					if(blacklisted):
						print string_ip + " found in blacklist"
						self.dataBackend.insert("blacklist_badhosts", {"bucket" : startBucket, "blacklist" : bl_adr, "black_host" : ele["sourceIPv4Address"], "black_host_string" : string_ip, "count" : count})


		if(query):			
			#data = {"easy" : False, "count_more" : 1}
			data = {"easy" : False, "include_list" : ["zen.spamhaus.org"]}
			self.dataBackend.query2("blacklist_badhosts", data)
			self.dataBackend.print_cursor()

		if(aggregate):
			#self.dataBackend.aggregate("blacklist_badhosts", {"group" : ["blackip", "blacklist"], "sum" : ["appearance"]} )
			self.dataBackend.aggregate("blacklist_badhosts", {"group" : ["black_hosts", "blacklist"],  "sum" : ["count"], "show" : ["count"] , "limit" : 200, "skip" : 0, "sort" : ["count"]} )
		

			#self.dataBackend.aggregate("blacklist_badhosts", {"sum" : ["count"]} )
			#aggregate( { $group : {_id : "$black_host_string", total : { $sum : "$count" } } }, { $match : { total : { $gte : 2 } } }
			#db.blacklist_badhosts.aggregate( { $group : {_id : "$blacklist", total : { $sum : "$count" } } }, { $match : { total : { $gte : 2 } } } );

