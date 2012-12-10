from analysis_base import AnalysisBase

import config
import common

class ServiceDetector(AnalysisBase):
	def __init__(self, flowbackend, databackend):
		AnalysisBase.__init__(self, flowbackend, databackend)


	def analyze(self, startBucket, endBucket):

		tableName = common.DB_FLOW_PREFIX + str(config.flow_bucket_sizes[0])

		service = {}

		min_conn = 1 # min. number of connections to be accepted as a service
		min_hosts = 1 # min. number of hosts, which have to use the port to be accepted as a service
		min_packet = 3 # min. number of packets which have to be sent as a response, if a service port is triggered 
		proto = 6 # examine protocol number ...
		
		# get all possible service ports by looking at destinationTransportPort as target
		res = self.flowBackend.run_query(tableName, "SELECT packetDeltaCount, protocolIdentifier, sourceIPv4Address, sourceTransportPort, destinationIPv4Address, destinationTransportPort, \
		COUNT(destinationTransportPort) AS access_tries \
		FROM %s WHERE bucket = " + str(startBucket) + " AND protocolIdentifier = " + str(proto) + " GROUP BY sourceIPv4Address, destinationTransportPort ORDER BY destinationTransportPort ASC")

		for obj in res:
			service_ip = obj["destinationIPv4Address"]
			service_port = obj["destinationTransportPort"]
			client_ip = obj["sourceIPv4Address"]
			tries = obj["access_tries"]

			#  check if there is a response 
			res2 = self.flowBackend.run_query(tableName, "SELECT bucket, protocolIdentifier, sourceIPv4Address, sourceTransportPort, \
			destinationIPv4Address, destinationTransportPort, packetDeltaCount, octetDeltaCount, flows, COUNT(*) AS rf \
			FROM %s WHERE bucket = " + str(startBucket) + " AND sourceIPv4Address = " + str(service_ip) + " AND packetDeltaCount >= " + \
			str(min_packet) + " AND destinationIPv4Address = " + str(client_ip) + " AND protocolIdentifier = " + str(proto) + " \
			AND sourceTransportPort = " + str(service_port))

			# calculate failed service requests
			fail = tries - res2[0]["rf"]

			# update results with calculated values
			obj.update({"access_fails" : fail, "access_success" : tries - fail})

			# insert all hosts (+ information), which try to use a service 
			#self.dataBackend.insert("service", obj)

			# sum up all service requests by using the tuple ip and port of the service as aggregation parameters 
			if((service_ip, service_port) in service):
				(t, s, f, h) = service[(service_ip, service_port)]		
			else:
				t = 0
				f = 0
				h = 0
			
			t+=tries
			f+=fail	
			h+=1
			       
			service.update({(service_ip, service_port) : (t, t - f, f, h)})

		# do some pre-filtering and put aggregation in database
		for se in service:
			(t, s, f, h) = service[se]	
			(service_host, port) = se
						
			if((t >= min_conn) and (h >= min_hosts)):
				#self.dataBackend.insert("service_aggr", {"bucket" : startBucket, "service_host" : service_host, "service_port" : port, "access_tries" : t, "access_success" : s, \
				#"access_success_per" : float(s) / float(t) * 100.0, "access_fails" : f, "access_fails_per" : float(f) / float(t) * 100.0, "hosts_count" : h})
				pass

		# queries
		data = {"easy" : False, "success_more" : 1}
		#self.dataBackend.query2("service", data)
		#self.dataBackend.print_cursor()
		
		data = {"easy" : False, "success_per_more" : 30.0}
		self.dataBackend.query2("service_aggr", data)
		self.dataBackend.print_cursor()

