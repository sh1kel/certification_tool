HW Verification tool usage
--------------------------

1. Environment setup
--------------------

* Setup fuel http://docs.mirantis.com/openstack/fuel/fuel-6.0/user-guide.html#download-and-install-fuel
* You need a bash console on a computer, which have access to fuel master node
  Try to execute 'wget FUEL_URL'. It should be successful.

* You need python 2.7
* Download verification tool from ....

* Install next packages: python-yaml, python-argparse, python-netaddr, 
	python-keystoneclient
  	For ubuntu:

  		$ sudo apt-get install python-yaml python-argparse python-netaddr python-keystoneclient

  	For centos:

  		$ sudo yum install apt-get install python-yaml python-argparse python-netaddr python-keystoneclient

* Run verification tool and pass FUEL url and auth parameters to it
* 
		$ ./cert_tool.sh -a LOGIN:PASSWD:TENANT FUEL_URL

	E.g.

		$ ./cert_tool.sh -a admin:admin:admin http://172.16.50.200:8000/

	Verification tool would use all nodes, available at the moment 
	(but not less than two). If you would like to create cluster not
	smaller that XX nodes size - add '--min-nodes XX' parameter. E.g.:

		$ ./cert_tool.sh -a admin:admin:admin --min-nodes 10 http://172.16.50.200:8000/

* Follow the mesages. When all slave nodes would be ready tool would create 
  test cluster and ask you to setup network parameters:

		> Please go to FUEL_CLUSTER_URL and configure network parameters. Then input 'ready' to continue :

  Open shown FUEL_CLUSTER_URL in our browser, login into FUEL and setup all 
  required network, parameters, accordingly to 
  http://docs.mirantis.com/openstack/fuel/fuel-6.0/user-guide.html#neutron-network-settings

  Then type 'ready' and press enter. Tool shoud proceede with clusater 
  installation. When installation finishes tool would run test and print report
  to screen. Also report would be save into filewitj name like 
  HW_cert_report_XXXX.txt, where XXXX would be current unix time.

