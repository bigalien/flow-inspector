"""
Flow Inspector maintains a number of information that are different from flow data.
This information includes the system configuration, or analysis results of background
data. 
Because a user might decide to store his flows in some kind of specialized flow database,
another backend is necessary if the flow backend does not support data other than flows
(this can for example happen if the nfdump or SiLK tools are used to manage the flow
information).
Supported backends:
	- mysql
	- oracle

Author: Lothar Braun 
"""

import sys

class Backend:
	def __init__(self, host, port, user, password, databaseName):
		self.host = host
		self.port = port
		self.user = user
		self.password = password
		self.databaseName = databaseName

	def connect(self):
		pass

	def prepareCollection(self, name, fieldDict):
		pass

	def query(self, collectionName, string):
		pass

	def query2(self, collectionName, data):
		pass

	def insert(self, collectionName, fieldDict):
		pass

	def data_query(self, collectionNames, fields):
		pass

	def data_aggregate(self):
		pass

class MongoDBBackend(Backend):
	def __init__(self, host, port, user, password,databaseName):
		import pymongo
		Backend.__init__(self, host, port, user, password, databaseName)
		self.connect()
		print "init"

	def prepareCollection(self, name, fieldDict):
		print "prep"
		

	def connect(self):
		import pymongo
		try:
			print "connect testverbindung"
			self.con = pymongo.Connection(self.host, self.port)
			self.db = self.con[self.databaseName]

		except:
			print >> sys.stderr, "Cannont connect to MongoDB"
			sys.exit(1)

	def insert(self, collectionName, fieldDict):
		import pymongo	
		try:
			print "insert"
			coll = self.db[collectionName]
			coll.insert(fieldDict)
		except:
			print >> sys.stderr, "MongoDB insert error"
			sys.exit(1)

	

	def query(self, collectionName, string):
		import pymongo

		try:	
			print "query"
			coll = self.db[collectionName]
			self.cursor = coll.find({"sourceTransportPort" : {"$gte" : 5000}})
			return self.cursor #.sort("sourceTransportPort")
		except:
			print >> sys.stderr, "MongoDB query error"
			sys.exit(1)

	def query2(self, collectionName, data):
		import pymongo

		keys = {"sourceTransportPort" : ["s_ports_greater", "s_ports_smaller", "s_include_ports", "s_exclude_ports"],
			"destinationTransportPort" : ["d_ports_greater", "d_ports_smaller", "d_include_ports", "d_exclude_ports"],
			"sourceIPv4Address" : ["null", "null", "s_include_address", "s_exclude_address"],
			"destinationIPv4Address" : ["null", "null", "d_include_address", "d_exclude_address"],
			"protocolIdentifier" : ["null", "null", "include_protocol", "exclude_protocol"],
			"packetDeltaCount" : ["packets_more", "packets_less", "null", "null"],
			"octetDeltaCount" : ["bytes_more", "bytes_less", "null", "null"],
			"flows" : ["flows_more", "flows_less", "null", "null"],
			"access_fails" : ["fails_more", "fails_less", "null", "null"],
			"access_fails_per" : ["fails_per_more", "fails_per_less", "null", "null"],
			"access_tries" : ["tries_more", "tries_less", "null", "null"],
			"access_success" : ["success_more", "success_less", "null", "null"],
			"access_success_per" : ["success_per_more", "success_per_less", "null", "null"],
			"hosts_count" : ["hosts_more", "hosts_less", "null", "null"],
			"black_hosts" : ["null", "null", "include_address", "exclude_address"],
			"blacklist" : ["null", "null", "include_list", "exclude_list"],
			"count" : ["count_more", "count_less", "null", "null"]}


		try:	
			self.qu = {}
			coll = self.db[collectionName]
			

			if(data.get("easy", False) == True):
				self.cursor = coll.find({})
				return self.cursor #.sort("sourceTransportPort")
			#else:
			#	if(data.get("s_ports_greater", False)):
			#		self.qu["sourceTransportPort"].update({"$gt" : data["s_ports_greater"]})
					
			#	if(data.get("s_ports_smaller", False)):
			#		self.qu["sourceTransportPort"].update({"$lt" : data["s_ports_smaller"]})

			#	if(data.get("s_include_ports", False)):
			#		self.qu["sourceTransportPort"].update({"$in" : data["s_include_ports"]})
					
			#	if(data.get("s_exclude_ports", False)):
			#		self.qu["sourceTransportPort"].update({"$nin" : data["s_exclude_ports"]})


			else:
				for k in keys.keys():
					if(data.get(keys[k][0], False)):

						if(k not in self.qu): self.qu.update({k : {}})					
	
						self.qu[k].update({"$gt" : data[keys[k][0]]})
					
					if(data.get(keys[k][1], False)):
						if(k not in self.qu): self.qu.update({k : {}})
						self.qu[k].update({"$lt" : data[keys[k][1]]})

					if(data.get(keys[k][2], False)):
						if(k not in self.qu): self.qu.update({k : {}})
						self.qu[k].update({"$in" : data[keys[k][2]]})
					
					if(data.get(keys[k][3], False)):
						if(k not in self.qu): self.qu.update({k : {}})
						self.qu[k].update({"$nin" : data[keys[k][3]]})
									
			self.cursor = coll.find(self.qu)
			print self.qu
			return self.cursor 

		except:
			print >> sys.stderr, "MongoDB query error"
			sys.exit(1)

	def print_cursor(self):
		for obj in self.cursor:
			print obj

	def aggregate(self, collectionName, com):
		import pymongo

		keys = {"black_hosts" : "black_host_string",
			"blacklist" : "blacklist",
			"count" : "count"}

		qu = {}
		group = {}
		su = {}
		pr = {}
		li = {}
		sk = {}
		srt = {}

		for k in com.keys():
			if(k == "group"):
				print "grouping"				
				
				for ele in com["group"]:
					group.update({ele : "$" + keys[ele]})
			
			if(k == "sum"):
				print "summing"

				for ele in com["sum"]:
					su.update({ele : {"$sum" : "$" + keys[ele]}})
			
			qu.update({"$group" : {"_id" : group}})
			qu["$group"].update(su)

			if(k == "show"):
				print "show"
				
				for ele in com["show"]:
					pr.update({keys[ele] : 1})
			pr.update({"_id" : 1})

			if(k == "limit"):
				print "limit"

				li.update({"$limit" : com["limit"]})

			if(k == "skip"):
				print "skip"
		
				sk.update({"$skip" : com["skip"]})

			if(k == "sort"):
				print "sort"
	
				for ele in com["sort"]:
					srt.update({keys[ele] : 1})

			
						

		
		agg = self.db[collectionName].aggregate([qu, {"$project" : pr}, sk, li, {"$sort" : srt}])	
		print agg["result"]

		
		#tmp = self.db[collectionName].aggregate( [{ "$group" : {"_id" : { "tmp1" : "$black_host_string"}, "total" : { "$sum" : "$count" } } }] )
		#tmp = self.db[collectionName].aggregate( [ { "$group" : {"_id" : "$black_host_string", "total" : { "$sum" : "$count" }, "total2" : { "$sum" : "$count" } }},  {"$project" : {"_id" : 1, "total2" : 1}}])
		#tmp = self.db[collectionName].aggregate( [{ "$group" : {"_id" : "$blacklist", "total" : { "$sum" : "$count" } } } ]);

		#tmp = self.db[collectionName].aggregate( [{ "$project" : {"_id" : 0, "black_host_string" : 1}} ]);
		#print "begin find"
		#print tmp["result"]		
		
		#tmp = self.db[collectionName].aggregate([{"$group": {"_id": {"blacklist": "$blacklist", "blackip": "$black_host_string"}, "appearance": {"$sum": "$count"}}])
		
		#for obj in tmp:
		#	print obj["result"]
#		print "end find"	

	
#, { "$match" : { "total" : { "$gte" : 2 } } }

#, {"$project" : {"total" : 1, "_id" : 0}}

class MySQLBackend(Backend):
	def __init__(self, host, port, user, password, databaseName):
		import MySQLdb
		Backend.__init__(self, host, port, user, password, databaseName)

	def connect(self):
		import MySQLdb
		import _mysql_exceptions
		try:
			dns = dict(
				db = self.databaseName,
				host = self.host,
				port = self.port,
				user = self.user,
				passwd = self.password
			)         
			self.conn = MySQLdb.connect(**dns)
			self.cursor = self.conn.cursor(MySQLdb.cursors.DictCursor)
		except Exception as inst:
			print >> sys.stderr, "Cannot connect to MySQL database: ", inst 
			sys.exit(1)


	def execute(self, string):
		import MySQLdb
		import _mysql_exceptions
		
		try: 
			self.cursor.execute(string)
		except (AttributeError, MySQLdb.OperationalError):
			self.connect()
			self.execute(string)

	def executemany(self, string, objects):
		import MySQLdb
		import _mysql_exceptions
		try:
			self.cursor.executemany(string, objects)
		except (AttributeError, MySQLdb.OperationalError):
			self.connect()
			self.executemany(strin, objects)


	def prepareCollection(self, name, fieldDict):
		createString = "CREATE TABLE IF NOT EXISTS " + name + " ("
		first = True
		primary = ""
		for field in fieldDict:
			if not first:
				createString += ","
			createString += field + " " + fieldDict[field][0]
			if fieldDict[field][1] != None:
				primary = " PRIMARY KEY(" + field + ")"
			first = False
		if primary != "":
			createString += "," + primary
		createString += ")"
		self.execute(createString)


	def query(self, tablename, string):
		string = string % (tableName)
		self.execute(string)
		return self.cursor.fetchall()

	def insert(self, collectionName, fieldDict):
		queryString = "INSERT INTO " + collectionName + " ("
		typeString = ""
		valueString = ""
		updateString = ""
		for field in fieldDict:
			if typeString != "":
				typeString += ","
			if valueString != "":
				valueString += ","
			if updateString != "":
				updateString += ","
			updateString += field + "=" "VALUES(" + field + ")"
			typeString += field
			valueString += str(fieldDict[field])

		queryString += typeString + ") VALUES (" + valueString + ") ON DUPLICATE KEY UPDATE " + updateString

		self.execute(queryString)

class OracleBackend(Backend):
	def __init__(self, host, port, user, password, databaseName):
		Backend.__init__(self, host, port, user, password, databaseName)
		self.doCache = False
		self.connect()

	def connect(self):
		import cx_Oracle
		try:
			connection_string = self.user + "/" + self.password + "@" + self.host + ":" + str(self.port) + "/" + self.databaseName
			self.conn = cx_Oracle.Connection(connection_string)
			self.cursor = cx_Oracle.Cursor(self.conn)
		except Exception as inst:
			print >> sys.stderr, "Cannot connect to Oracle database: ", inst 
			#sys.exit(1)


	def execute(self, string, params = None):
		import cx_Oracle
		try: 
			if params == None:
				self.cursor.execute(string)
			else:
				self.cursor.execute(string, params)
			self.conn.commit()
		except (AttributeError, cx_Oracle.OperationalError) as e:
			print e
			self.connect()
			self.execute(string)
		except cx_Oracle.DatabaseError as e:
			print e
			error, = e.args
			if error.code == 955:
				print "Table already exists!"
			else:
				print e
				print "DataBackend: Have seen unknown error. Terminating!"
				sys.exit(-1)

	def prepareCollection(self, name, fieldDict):
		createString = "CREATE TABLE  " + name + " ("
		first = True
		primary = ""
		for field in fieldDict:
			if not first:
				createString += ","
			createString += field + " " + fieldDict[field][0]
			if fieldDict[field][1] != None:
				primary = " PRIMARY KEY(" + field + ")"
			first = False
		if primary != "":
			createString += "," + primary
		createString += ")"
		self.execute(createString)


	def query(self, tablename, string):
		string = string % (tablename)
		self.execute(string)
		return self.cursor.fetchall()

	def insert(self, collectionName, fieldDict):
		queryString = "MERGE INTO " + collectionName + " target USING (SELECT "
		selectString = ""
		matchedString = ""
		notMatchedInsert = ""
		notMatchedValues = ""
		primary = ""
		params = {}
		for field in fieldDict:
			if selectString != "":
				selectString += ","
			if notMatchedInsert != "":
				notMatchedInsert += ","
			if notMatchedValues != "":
				notMatchedValues += ","
			selectString += ":"+field  + " as " + field
			params[field] = str(fieldDict[field][0])
			if fieldDict[field][1] != "PRIMARY":
				if matchedString != "":
					matchedString += ","
				if fieldDict[field][1] == None or fieldDict[field][1] == "ADD":
						matchedString += field + "=" + "SOURCE." + field + "+" + "target." + field
				elif fieldDict[field][1] == "UPDATE":
						matchedString += field + "=" + "target." + field
				elif fieldDict[field][1] == "KEEP":
						matchedString += field + "=" + "SOURCE." + field

			notMatchedInsert += "target." + field
			notMatchedValues += "SOURCE." + field
			if fieldDict[field][1] == "PRIMARY":
				if primary != "":
					primary += " AND "
				primary += "target." + field + "=SOURCE." + field
		
		queryString += selectString + " FROM dual) SOURCE ON (" + primary + ")"
		queryString += "WHEN MATCHED THEN UPDATE SET " + matchedString
		queryString += " WHEN NOT MATCHED THEN INSERT (" + notMatchedInsert + ") VALUES (" + notMatchedValues + ")" 
		if self.doCache:
			numElem = 1
			if collectionName in self.tableInsertCache:
				cache = self.tableInsertCache[collectionName][0]
				numElem = self.tableInsertCache[collectionName][1] + 1
				if queryString in cache:
					cache[queryString].append(params)
				else:
					cache[queryString] = [ params ]
			else:
				cache = dict()
				cache[queryString] = [ params ]
		
			self.tableInsertCache[collectionName] = (cache, numElem)

			self.counter += 1
			#if self.counter % 100000 == 0:
				#print "Total len:",  len(self.tableInsertCache)
				#for c in self.tableInsertCache:
					#print c, len(self.tableInsertCache[c][0]), self.tableInsertCache[c][1]
			
			if numElem > self.cachingThreshold:
				self.flushCache(collectionName)
		else:
			self.execute(queryString, params)


	def data_query(self, collectionName, fields):
		queryString = "SELECT * FROM %s"
		rows =  self.query(collectionName, queryString)
		desc = [d[0] for d in self.cursor.description]
		result = [dict(zip(desc,line)) for line in rows]
		return result

		



def getBackendObject(backend, host, port, user, password, databaseName):
	if backend == "mysql":
		return MySQLBackend(host, port, user, password, databaseName)
	elif backend == "oracle":
		return OracleBackend(host, port, user, password, databaseName)
	elif backend == "mongo":
		print "gebe mongo zurueck"
		return MongoDBBackend(host, port, user, password, databaseName)
	else:
		raise Exception("Data backend " + backend + " is not a supported backend")
