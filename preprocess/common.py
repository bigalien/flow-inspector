import os 


# flow time interval column names
COL_FIRST_SWITCHED = "firstSwitched"
COL_LAST_SWITCHED = "lastSwitched"
# column names of IP addresses
COL_SRC_IP = "srcIP"
COL_DST_IP = "dstIP"
# column names of ports and protocol
COL_SRC_PORT = "srcPort"
COL_DST_PORT = "dstPort"
COL_PROTO = "proto"

# the collection prefix to use for flows
DB_FLOW_PREFIX = "flows_"
# the collection prefix to use for completely aggregated flows
DB_FLOW_AGGR_PREFIX = "flows_aggr_"
# the collection to use for the node index
DB_INDEX_NODES = "index_nodes"
# the collection to use for the port index
DB_INDEX_PORTS = "index_ports"


INDEX_ADD = "add"
INDEX_REMOVE = "remove"

IGNORE_COLUMNS = ["firstSwitchedMillis", "lastSwitchedMillis"]

# Print output every ... in seconds
OUTPUT_INTERVAL = 10

# the xml file containing known port numbers
PORTS_FILE = os.path.join(os.path.dirname(__file__), '..', 'config', 'service-names-port-numbers.xml')

REDIS_QUEUE_KEY = "entry:queue"



def update_node_index(obj, collection, aggr_sum, operation):
	"""Update the node index collection in MongoDB with the current flow.
	
	:Parameters:
	 - `obj`: A dictionary containing a flow.
	 - `collection`: A pymongo collection to insert the documents.
	 - `aggr_sum`: A list of keys which will be sliced and summed up.
	 - `operation`: Whether to add or remove the flow to/from the index
	"""

	# logic check. operation must be either INDEX_ADD or INDEX_REMOVE
	if operation != INDEX_ADD and operation != INDEX_REMOVE:
		raise Exception("Logic Error: operation is neither INDEX_ADD nor INDEX_REMOVE")
	
	# update source node
	doc = { "$inc": {} }
	
	for s in aggr_sum:
		if operation == INDEX_ADD:
			doc["$inc"][s] = obj.get(s, 0)
			doc["$inc"]["src." + s] = obj.get(s, 0)
		else:
			doc["$inc"][s] = -obj.get(s, 0)
			doc["$inc"]["src." + s] = -obj.get(s, 0)


	if operation == INDEX_ADD:
		doc["$inc"]["flows"] = 1
		doc["$inc"]["src.flows"] = 1
	else:
		# remove 
		doc["$inc"]["flows"] = -obj.get("flows")
		doc["$inc"]["src.flows"] = -obj.get("flows") 
	
	# insert if not exists, else update sums
	collection.update({ "_id": obj[COL_SRC_IP] }, doc, True)
	
	# update destination node
	doc = { "$inc": {} }
	
	for s in aggr_sum:
		if operation == INDEX_ADD:
			doc["$inc"][s] = obj.get(s, 0)
			doc["$inc"]["dst." + s] = obj.get(s, 0)
		else:
			doc["$inc"][s] = -obj.get(s, 0)
			doc["$inc"]["dst." + s] = -obj.get(s, 0)

	if operation == INDEX_ADD:
		doc["$inc"]["flows"] = 1
		doc["$inc"]["dst.flows"] = 1
	else:
		# remove 
		doc["$inc"]["flows"] = -obj.get("flows")
		doc["$inc"]["dst.flows"] = -obj.get("flows") 
					
	# insert if not exists, else update sums
	collection.update({ "_id": obj[COL_DST_IP] }, doc, True)
	
def update_port_index(obj, collection, aggr_sum, filter_ports, operation):
	"""Update the port index collection in MongoDB with the current flow.
	
	:Parameters:
	 - `obj`: A dictionary containing a flow.
	 - `collection`: A pymongo collection to insert the documents.
	 - `aggr_sum`: A list of keys which will be sliced and summed up.
	 - `filter_ports`: A dictionary of ports and protocols to remove unknown ports
	 - `operation`: Whether to add or remove the flow to/from the index.
	"""
	
	# update source port
	doc = { "$inc": {} }

	for s in aggr_sum:
		if operation == INDEX_ADD:
			doc["$inc"][s] = obj.get(s, 0)
			doc["$inc"]["src." + s] = obj.get(s, 0)
		else:
			doc["$inc"][s] = -obj.get(s, 0)
			doc["$inc"]["src." + s] = -obj.get(s, 0)


	if operation == INDEX_ADD:
		doc["$inc"]["flows"] = 1
		doc["$inc"]["src.flows"] = 1
	else:
		# remove 
		doc["$inc"]["flows"] = -obj.get("flows")
		doc["$inc"]["src.flows"] = -obj.get("flows") 
		

	# set unknown ports to None
	port = obj.get(COL_SRC_PORT, None)
	if filter_ports and port != None:
		if port in filter_ports:
			proto = int(obj.get(COL_PROTO, -1))
			if proto >= 0 and not proto in filter_ports[port]:
				port = None
		else:
			port = None
	
	# insert if not exists, else update sums
	collection.update({ "_id": port }, doc, True)
	
	# update destination port
	doc = { "$inc": {} }

	for s in aggr_sum:
		if operation == INDEX_ADD:
			doc["$inc"][s] = obj.get(s, 0)
			doc["$inc"]["dst." + s] = obj.get(s, 0)
		else:
			doc["$inc"][s] = -obj.get(s, 0)
			doc["$inc"]["dst." + s] = -obj.get(s, 0)

	if operation == INDEX_ADD:
		doc["$inc"]["flows"] = 1
		doc["$inc"]["dst.flows"] = 1
	else:
		# remove 
		doc["$inc"]["flows"] = -obj.get("flows")
		doc["$inc"]["dst.flows"] = -obj.get("flows") 
		
	for s in aggr_sum:
		doc["$inc"][s] = obj.get(s, 0)
		doc["$inc"]["dst." + s] = obj.get(s, 0)
	doc["$inc"]["flows"] = 1
	doc["$inc"]["dst.flows"] = 1
	
	# insert if not exists, else update sums
	collection.update({ "_id": port }, doc, True)


# read ports for special filtering
def getKnownPorts(flow_filter_unknown_ports):
	known_ports = None
	if flow_filter_unknown_ports:
		f = open(common.PORTS_FILE, "r")
		dom = xml.dom.minidom.parse(f)
		f.close()
	
		def getDomText(node):
			rc = []
			for n in node.childNodes:
				if n.nodeType == node.TEXT_NODE:
					rc.append(n.data)
			return ''.join(rc)

		known_ports = dict()
		records = dom.getElementsByTagName("record")
		for record in records:
			description = getDomText(record.getElementsByTagName("description")[0])
			number = record.getElementsByTagName("number")
			if description != "Unassigned" and len(number) > 0:
				numbers = getDomText(number[0]).split('-')
				number = int(numbers[0])
				number_to = int(numbers[len(numbers)-1])
				
				protocol = record.getElementsByTagName("protocol")
				if len(protocol) > 0:
					protocol = getDomText(protocol[0])
					if protocol == "tcp":
						protocol = 6
					elif protocol == "udp":
						protocol = 17
					else:
						protocol = 0
				else:
					protocol = 0
				
				while number <= number_to:
					if number in known_ports:
						known_ports[number].append(protocol)
					else:
						known_ports[number] = [protocol]
					number += 1