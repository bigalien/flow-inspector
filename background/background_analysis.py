#!/usr/bin/env python 

import sys
import os.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'config'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

from network_scan_detector import NetworkScanDetector
#from host_information_checker import HostInformationChecker
from simon_test import SimonTest
from service_detector import ServiceDetector
from dnsbl import DNSblack
#import flowbackend
#import databackend
import backend
import config
import common

if __name__ == "__main__":
	flowdb = backend.flowbackend.getBackendObject(config.db_backend, config.db_host, config.db_port, config.db_user, config.db_password, config.db_name)
	datadb = backend.databackend.getBackendObject(config.data_backend, config.data_backend_host, config.data_backend_port, config.data_backend_user, config.data_backend_password, config.data_backend_name)

	if len(sys.argv) == 2:
		startBucket = int(sys.argv[1])
		endBucket = int(sys.argv[2])
		print "Using start and endtime from command line arguments. startbucket: ", startBucket, " endBucket: ", endBucket
	else:
		startBucket = flowdb.getMinBucket()
		endBucket = flowdb.getMaxBucket()
		print "Analysing data in buckets: [", startBucket, ", ", endBucket, "]"

#	networkScanDetector = NetworkScanDetector(flowdb, datadb)
#	hostInformationChecker = HostInformationChecker(flowdb, datadb)
#	simonTest = SimonTest(flowdb, datadb)

#	serviceDetector = ServiceDetector(flowdb, datadb)

	dnsbl = DNSblack(flowdb, datadb)

	# use smallest bucket size 
	slidingBucketSize = config.flow_bucket_sizes[0]
	for bucket in range(startBucket, endBucket, slidingBucketSize):
		#print "Analyzing data in bucket: ", bucket
		#networkScanDetector.analyze(bucket, bucket)
		#hostInformationChecker.analyze(bucket, bucket)
		#simonTest.analyze(bucket, bucket)

#		serviceDetector.analyze(bucket, bucket)

		dnsbl.analyze(bucket, bucket)
