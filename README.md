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


Approach 1
- Create General learning switch rule 
- Start with general rules
- Keep an eye on the traffic size
- Expand and DPI and install more rules when traffic size of a cluster exceeds threshold


Approach 2 (May 3 Commit)
- Install general learning switch rules 
- Keep collecting data and create general clusters 
- Upon detecting anomaly 
	- Get the corresponding rule for the concerned cluster 
	- Change the rule to send packet to the controller 
	- Get the packet information and get keep creating more specific flows with the packet attributes 
		- For each flow there will be a separate cluster 
		- For the unique flow it will the cluster size is significant keep that rule 
		
		

Update April 28 Commit 

1. New Stat Collector
2. New thread management, each operation runs in separate threats
3. Cluster management e.g. Create Cluster, update counts. track flows , etc.
4. Added Learning Switch logic.
5. Generate Report (only the basic one for now)
6. Relate Flow with Clusters 
7. Miscellanious

Update May 3 Commit 
Sample Output

Cluster--0	 ---- 	*	 ---- 	*	 ---- 	*	 ---- 	*	 ---- 	ALL	 ---- 	100.0% 	 ---- 	100.0% 
Cluster--3	 ---- 	*	 ---- 	*	 ---- 	*	 ---- 	*	 ---- 	ICMP	 ---- 	100.0% 	 ---- 	100.0% 
Cluster--10	 ---- 	10.0.0.2/0	 ---- 	10.0.0.1/0	 ---- 	0	 ---- 	0	 ---- 	ICMP	 ---- 	25.0% 	 ---- 	25.0% 
Cluster--11	 ---- 	10.0.0.1/0	 ---- 	10.0.0.2/0	 ---- 	0	 ---- 	0	 ---- 	ICMP	 ---- 	25.0% 	 ---- 	25.0% 
Cluster--12	 ---- 	10.0.0.3/0	 ---- 	10.0.0.2/0	 ---- 	0	 ---- 	0	 ---- 	ICMP	 ---- 	25.0% 	 ---- 	25.0% 
Cluster--13	 ---- 	10.0.0.2/0	 ---- 	10.0.0.3/0	 ---- 	0	 ---- 	0	 ---- 	TCP	 ---- 	25.0% 	 ---- 	25.0% 
 Total Number of Packets: 156 Total Traffic: 0.015 MB 