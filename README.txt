
----------------------------------------------------------------------
Addition Security STIX Toolkit
----------------------------------------------------------------------
Copyright 2019 J Forristal LLC.
Copyright 2016 Addition Security, Inc. 
STIX and CybOX are a registered trademarks of The MITRE Corporation.


SUMMARY
==========
The Addition Security STIX Toolkit contains working reference
implementation and examples of parsing Addition Security's binary
protobuf format and producing formal STIX XML using the official
STIX python modules.


PREREQUISITES
=============
- Python 2.7
- The following python modules (installable via "pip install"):
--- stix
--- cybox
--- protobuf


CONTENTS
========
implementation/addsec_to_stix.py - Main executable script
implementation/addsec_cti_pb2.py - Addition Security python protobuf module
implementation/definitions.json - Addition Security message definitions
implementation/example_msg.bin - Example Addition Security binary message
protobuf/addsec_cti.proto - Addition Security binary protobuf specification


EXECUTION
=========
Within the implementation/ directory, run:
	python addsec_to_stix.py example_msg.bin

The script will load the example_msg.bin binary message file, parse it, and
output STIX appropriate XML representation.


