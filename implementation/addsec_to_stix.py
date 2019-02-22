#!/usr/bin/env python
#
# Copyright 2019 J Forristal LLC
# Copyright 2016 Addition Security Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# This script showcases the STIX representation used by Addition Security,
# and how it can be easily transformed into formal STIX XML.
#
#

# STIX and CybOX are registered trademarks of The MITRE Corporation.

import addsec_cti_pb2
import json
import datetime

from stix.core import STIXPackage
from stix.core import STIXHeader
from stix.report import Report
from stix.common import RelatedObservable
from stix.indicator.sightings import Sighting
from stix.indicator.indicator import Indicator

from cybox.common import Hash
from cybox.core.observable import Observable
from cybox.objects.product_object import Product
from cybox.objects.device_object import Device
from cybox.objects.api_object import API
from cybox.objects.library_object import Library
from cybox.objects.user_account_object import UserAccount
from cybox.objects.file_object import File
from cybox.objects.hostname_object import Hostname
from cybox.objects.x509_certificate_object import X509Certificate
from cybox.objects.process_object import Process
from cybox.objects.linux_package_object import LinuxPackage
from cybox.objects.artifact_object import Artifact
from cybox.objects.custom_object import Custom
from cybox.common.object_properties import CustomProperties, Property


from stix.utils import set_id_namespace
NAMESPACE = { 'http://www.addditionsecurity.com' : 'addsec' }
set_id_namespace( NAMESPACE )


##############################################################################
#
# The main transform function; takes Addition Security binary protobuf and returns STIX XML
#

def transform( addsec_data ):

	#
	# Parse the Addition Security protobuf object, which contains a STIX report representation
	#
	as_report = addsec_cti_pb2.Report()
	as_report.ParseFromString( addsec_data )


	#
	# Create a new STIX package & report container
	#
	stix_package = STIXPackage()
	stix_package.stix_header = STIXHeader()
	stix_package.stix_header.description = "Addition Security Report"
	stix_report = Report()


	#
	# Addition Security includes various identification information re: the entity of the report.
	# We are going to convert it into three CybOX objects: Product, Device, and Custom
	#

	cybox_product = Product()
	cybox_product.product = "MobileAwareness"
	cybox_product.vendor = "Addition Security"

	cybox_device = Device()
	cybox_device.device_type = "Mobile Device"

	cybox_custom_sourceapp = Custom()
	cybox_custom_sourceapp.custom_name = "addsec:sourceApplication"
	cybox_custom_sourceapp.custom_properties = CustomProperties()

	p = Property()
	p.name = "organizationId"
	p.value = as_report.organizationId.encode('hex')	# NOTE: this is binary bytes
	cybox_custom_sourceapp.custom_properties.append( p )

	p = Property()
	p.name = "application"
	p.value = as_report.applicationId			# NOTE: bundleId/packageId of hosting app
	cybox_custom_sourceapp.custom_properties.append( p )

	p = Property()
	p.name = "instanceId"
	p.value = as_report.systemId.encode('hex')		# NOTE: this is binary bytes
	cybox_custom_sourceapp.custom_properties.append( p )

	stix_report.add_observable( cybox_product )
	stix_report.add_observable( cybox_device )
	stix_report.add_observable( cybox_custom_sourceapp )


	#
	# Enumerate the Addition Security reported sightings
	#
	for as_sighting in as_report.observations:

		#
		# Addition Security lets customers transit custom messages over the reporting channel; these
		# messages show up as a "Customer Message" indicator with string-based payload.  Since these
		# messages are both proprietary in nature and potentially unrelated to STIX, we are going to
		# filter them out from this processing.
		# 
		if as_sighting.observationType == 8: continue    # 8: CustomerData


		#
		# Sightings are used to report device information as well; let's expel device-related
		# sightings and re-route their data into the CybOX device object (instead of including
		# as an indicator w/ sighting)
		#
		if as_sighting.testId == 1 or as_sighting.testId == 2:  #
			addsec_to_cybox_device( cybox_device, as_sighting )
			continue

		# Ditto for reported product information as well
		if as_sighting.testId == 8:  # 8: SDKVersionInfo
			addsec_to_cybox_product( cybox_product, as_sighting )
			continue
	
	
		#
		# Compose a STIX-appropriate indicator value from the Addition Security indicator ID & SubID
		#
		indicator_id = "addsec:asma-%d-%d" % (as_sighting.testId, as_sighting.testSubId)
		stix_indicator = Indicator( id_=indicator_id )
		stix_indicator.title = addsec_title_lookup( as_sighting.testId, as_sighting.testSubId )


		#
		# Create a sighting for this indicator
		#
		stix_sighting = Sighting()
		stix_indicator.sightings = stix_sighting 
		stix_sighting.timestamp = datetime.datetime.fromtimestamp( as_sighting.timestamp )
		if as_sighting.confidence > 0:
			stix_sighting.confidence = addsec_to_stix_confidence( as_sighting.confidence )


		#
		# Enumerate the observables for this sighting
		#
		for as_observable in as_sighting.datas:

			cybox_obj = addsec_to_cybox( as_observable.dataType, as_observable.data )
			if not cybox_obj is None:
				stix_sighting.related_observables.append( RelatedObservable(Observable(cybox_obj)) )


		#
		# Finally, add this indicator (w/ sightings & related observables) to the top level report
		#
		stix_report.add_indicator( stix_indicator )


	#
	# Finalize the STIX report and output the XML
	#
	stix_package.reports = stix_report 
	return stix_package.to_xml()




###################################################################################################
#
# Utility function to map Addition Security confidence values to STIX vocab values
#

def addsec_to_stix_confidence( as_conf ):
	if as_conf == 1: return "Low"
	if as_conf == 2: return "Medium"
	if as_conf == 3: return "High"
	return "Unknown"



###################################################################################################
#
# Utility function to take indicators containing device-related information, and put the observable
# data into a parent CybOX Device object (instead of representing device info as sightings of indicators)
#

def addsec_to_cybox_device( cybox_device, as_sighting ):
	#
	# Merge multiple separete reported sightings into a single CybOX device object
	#

	# 1: SystemHardwareInfo
	if as_sighting.testId == 1:
		cybox_device.model = as_sighting.datas[0].data

	# 2: SystemFirmwareInfo
	if as_sighting.testId == 2:
		cybox_device.firmware_version = as_sighting.datas[0].data

	# 3: SystemOSInfo
	# TODO - find the proper CybOX to report this




###################################################################################################
#
# Utility function to take indicators containing product-related information, and put the observable
# data into a parent CybOX Product object (instead of representing product info as sightings of indicators)
#

def _le_bytes_to_int( data ):
	v = 0
	for i in range(len(data)):
		v = v << 8
		v += ord(data[i])
	return v

def addsec_to_cybox_product( cybox_product, as_sighting ):
	#
	# Merge runtime SDK info into a CybOX product object
	#

	# 8: SDKVersionInfo
	if as_sighting.testId == 8:
		lib_version = 0
		defs_version = 0
		conf_ts = 0

		for d in as_sighting.datas:
			if d.dataType == 9: lib_version = _le_bytes_to_int(d.data)    	# DataTypeASLibVersion
			if d.dataType == 25: conf_ts = _le_bytes_to_int(d.data)    	# DataTypeASConfTimestamp
			if d.dataType == 26: defs_version = _le_bytes_to_int(d.data)   	# DataTypeASDefVersion

		cybox_product.version = "%d:%d:%d" % (lib_version, defs_version, conf_ts)



###################################################################################################
#
# Utility function to specifically handle sightings that have a combination of file path & file hash,
# so they can be merged into a single observable.  Addition Security reports specific application
# measurements that fits this format.
#

def addsec_to_cybox_file( as_observables ):
	f = File()
	for observable in as_observables:
		if observable.dataType == 10:  # DataTypeFile
			f.full_path = observable.data
		elif observable.dataType == 2: # DataTypeSHA1 (binary bytes)
			f.sha1 = Hash(observable.data.encode('hex'))
	return f



###################################################################################################
#
# Utility function to specifically handle sightings that have a combination of certificate subject
# and certificate hash, so they can be merged into a single observable.  Addition Security reports
# speicfic signing-related information that fits this format.
#
	
def addsec_to_cybox_cert( as_observables ):
	c = X509Certificate()
	for observable in as_observables:
		if observable.dataType == 11:  # DataTypeX509
			c.raw_certificate = observable.data
		elif observable.dataType == 12: # DataTypeX509Subject
			c.certificate.subject = observable.data
		elif observable.dataType == 13: # DataTypeX509Issuer
			c.certificate.issuer = observable.data
		elif observable.dataType == 2:  # DataTypeSHA1 (binary bytes)
			c.certificate_signature.signature = Hash(observable.data.encode('hex'))
	return c



###################################################################################################
#
# Utility function to represent singular/generic observables into CybOX representation
#

def addsec_to_cybox( as_obtype, as_obdata ):
	#
	# Addition Security to CybOX mappings, for discrete/separate observables
	#


	# 30: DataTypeSymbolName
	if as_obtype == 30:
		a = API()
		a.function_name = as_obdata
		return a

	# 32: DataTypeLibraryName
	if as_obtype == 32:
		l = Library()
		l.name = as_obdata
		l.path = as_obdata
		return l

	# 14: DataTypeUsername
	if as_obtype == 14:
		u = UserAccount()
		u.username = as_obdata
		return u

	# 10: DataTypeFile
	if as_obtype == 10:
		f = File()
		f.full_path = as_obdata
		return f

	# 23: DataTypeHostname
	if as_obtype == 23:
		h = Hostname()
		h.hostname_value = as_obdata
		return h

	# 29: DataTypeEnvString
	if as_obtype == 29:
		# Here, Process is meant to represent the hosting process; then we
		# attach the actual environment variable value
		p = Process()
		p.environment_variable_list = as_obdata
		return p

	# 17: DataTypeApplication
	if as_obtype == 17:
		# Particularly on Android, identification of an installed package fits
		# somewhere between File and Process, but not quite either.  The closest
		# fit is around LinuxPackage, which is what we use.  We should technically
		# derive from it, but we're trying to keep things simple.
		p = LinuxPackage()
		p.name = as_obdata
		return p

	# 11: DataTypeX509
	# 12: DataTypeX509Subject
	# 13: DataTypeX509Issuer
	if as_obtype == 11 or as_obtype == 12 or as_obtype == 13:
		c = X509Certificate()
		if as_obtype == 11: c.raw_certificate = as_obdata.encode('hex')
		if as_obtype == 12: c.certificate.subject = as_obdata
		if as_obtype == 13: c.certificate.issuer = as_obdata
		return c

	# 2: DataTypeSHA1Hash
	# 7: DataTypeVersionString
	# 18: DataTypeString
	# 31: DataTypePropertyName
	# TODO: find the proper CybOX to represent these; for now, we don't
	# report them
	return None




##############################################################################
#
# The following two functions relate to taking an Addition Security indicator
# ID and SubID, and using the definitions.json file (provided by Addition Security)
# to decode the ids into a title.  This is the same process used by the
# Addition Security Messaging Gateway.
#

_ADDSEC_DEFS_JSON = None

def addsec_title_lookup( id1, id2 ):
	sid1 = str(id1)
	sid2 = str(id2)

	if not _ADDSEC_DEFS_JSON['events'].has_key( sid1 ):
		return "(Untitled event %s/%s)" % (sid1, sid2)

	title = _ADDSEC_DEFS_JSON['events'][sid1]["0"]
	if _ADDSEC_DEFS_JSON['events'][sid1].has_key(sid2):
		title += " - " + _ADDSEC_DEFS_JSON['events'][sid1][sid2]

	return title


def addsec_definitions_load(fpath):
	with open( fpath, "r" ) as f:
		data = f.read()
	global _ADDSEC_DEFS_JSON
	_ADDSEC_DEFS_JSON = json.loads( data )
	if not _ADDSEC_DEFS_JSON.has_key('events'): raise Exception('bad definitions')



###############################################################################

if __name__ == "__main__":	
	import sys
	addsec_file_path = sys.argv[1]

	# Load an Addition Security definitions file, to get descriptions/titles
	addsec_definitions_load('definitions.json')

	# Load in a binary Addition Security protobuf message
	with open( addsec_file_path, "r" ) as f:
		data = f.read()

	# Transfrom the Addition Security message into STIX XML
	print transform( data )
