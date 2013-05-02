Floodlight-AD
=============

A Floodlight Module For Anomaly Detection 

Requirements

1. Add the GSON jar files to project library
2. Remove the built in LearningSwitch and Forwarding Modules

Test Instructions 
1. Run mininet 
2. Try pinging or use iperf. 
3. Read data from the log file 

Going with Approach 2 

- Install general learning switch rules 
- Keep collecting data and create general clusters 
- Upon detecting anomaly 
	- Get the corresponding rule for the concerned cluster 
	- Change the rule to send packet to the controller 
	- Get the packet information and get keep creating more specific flows with the packet attributes 
		- For each flow there will be a separate cluster 
		- For the unique flow it will the cluster size is significant keep that rule 
		- Delte otheres 
		
Questions We Ask From This Module 

In the given network 
	- Is there any destination host that's receiving ununusal traffic on a fixed port from a fixed source host?
	- Is there any destination host that's receiing unusual traffic on a fixed port from a set of different sources?
	- Is there any destination host 

Update April 28 Commit 

1. New Stat Collector
2. New thread management, each operation runs in separate threats
3. Cluster management e.g. Create Cluster, update counts. track flows , etc.
4. Added Learning Switch logic.
5. Generate Report (only the basic one for now)
6. Relate Flow with Clusters 
7. Miscellanious

