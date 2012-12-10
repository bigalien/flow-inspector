# -*- coding: utf-8 -*-
# Copy this file to config.py and edit configs

# Server
#----------------------------------------------------------------
host = "0.0.0.0"
port = 8080
debug = True

# Original Flow DB (mysql, postrgres, oracle)
#----------------------------------------------------------------
flowDBHost="127.0.0.1"
flowDBPort=3306
flowDBUser="root"
flowDBPassword="chefkoch"
flowDBName="flows_vermont_10"


# Destination Flow Backend (Default: MongoDB)
#----------------------------------------------------------------
db_backend = "mysql"
db_host = "127.0.0.1"
db_port = 3306
db_user = "root"
db_password = "chefkoch"
#db_name = "flows_fi_mytest9"
db_name = "flows_fi2"

# Destination Data Backend (for miscelanous data)
#----------------------------------------------------------------
data_backend = "mongo"
data_backend_host = "127.0.0.1"
data_backend_port = 27017
data_backend_user = None
data_backend_password = None
data_backend_name = "mydb"



# Flow settings
#----------------------------------------------------------------
# The different bucket sizes in seconds to aggregate.
# Each bucket size leads to a new collection in the database.
# This list is assumed be sorted ascending!
flow_bucket_sizes = [ 5*60 ]
# Those values have to match in order to aggregate two flows
flow_aggr_values = ["sourceIPv4Address", "destinationIPv4Address", "sourceTransportPort", "destinationTransportPort", "protocolIdentifier"]
# Those columns will be summed up
flow_aggr_sums = ["packetDeltaCount", "octetDeltaCount"]
# Special treatment for ports:
# Only consider known port numbers, set the others to null
# before aggregation.
flow_filter_unknown_ports = False

# Preprocessor settings
#----------------------------------------------------------------
# caching can reduce the amount of writes to Mongo
# cache size per bucket size
pre_cache_size = 10000
# cache size for aggregated collections per bucket size
pre_cache_size_aggr = 5


# Cleanup process settings
#----------------------------------------------------------------
# Important: preprocessor will not import any flows that are older
# (as in firstSwitched) than the default keep time if this value is 
# non zero.
max_flow_age = 0
 
# Host Information Datbase (optional)
#----------------------------------------------------------------
host_information_table = "somename"

