Floodlight-AD
=============
A Floodlight Module For Anomaly Detection 

Instructions to Run
1. Add the GSON jar files to project library
2. Remove the built in LearningSwitch and Forwarding Modules
3. Install new signatures for base clusters in DetectionUnit.java or Just use the existing ones
4. Build the project

Test Instructions 
1. Run mininet 
2. Try pinging or use iperf. 

	

Update April 28 Commit 

1. New Stat Collector
2. New thread management, each operation runs in separate threats
3. Cluster management e.g. Create Cluster, update counts. track flows , etc.
4. Added Learning Switch logic.
5. Generate Report (only the basic one for now)
6. Relate Flow with Clusters 
7. Miscellanious

Update May 15 Commit 
Sample Output

Cluster Label ---- Source IP 	----	Dest IP 	 ---- 	Src Port----	Dest Port----Protocol----PacketCount(%)----ByteCount(%) 
Cluster--0	 ---- 	*	 		---- 	*		 	 ---- 	*	 	---- 	*	 	---- 	ALL	 ---- 	100.0% 	 ---- 	100.0% 
Cluster--1	 ---- 	*	 		---- 	*		 	 ---- 	*	 	---- 	*	 	---- 	TCP	 ---- 	93.0% 	 ---- 	92.4% 
Cluster--2	 ---- 	*	 		---- 	*	 	 	 ---- 	*	 	---- 	*	 	---- 	ICMP ---- 	7.0% 	 ---- 	6.6% 
Cluster--3	 ---- 	10.0.0.0/16	---- 	*	 	 	 ---- 	*	 	---- 	*	 	---- 	TCP	 ---- 	93.0% 	 ---- 	92.4% 
Cluster--4	 ---- 	*			---- 	10.0.0.0/16	 ---- 	*	 	---- 	*	 	---- 	TCP	 ---- 	93.0% 	 ---- 	92.4% 
Cluster--5	 ---- 	10.0.0.1/0	---- 	*	 	 	 ---- 	*	 	---- 	*	 	---- 	TCP	 ---- 	48.0% 	 ---- 	48.0% 
Cluster--6	 ---- 	10.0.0.64/0	---- 	*	 	 	 ---- 	*	 	---- 	*	 	---- 	TCP	 ---- 	45.0% 	 ---- 	45.0% 
Cluster--11	 ---- 	10.0.0.64/0	----	10.0.0.56/0	 ---- 	-26329	---- 	-26329	---- 	TCP	 ---- 	25.0% 	 ---- 	25.0% 
Cluster--12	 ---- 	10.0.0.64/0	---- 	10.0.0.54/0	 ---- 	-28684	---- 	-28684	---- 	TCP	 ---- 	20.0% 	 ---- 	19.8% 
Cluster--14	 ---- 	10.0.0.1/0	---- 	10.0.0.55/0	 ---- 	-12345	---- 	-12345	---- 	TCP	 ---- 	23.0% 	 ---- 	22.6% 
Cluster--13	 ---- 	10.0.0.1/0	---- 	10.0.0.53/0	 ---- 	-20100	---- 	-20100	---- 	TCP	 ---- 	25.0% 	 ---- 	25.0% 
Cluster--7	 ---- 	10.0.0.2/0	---- 	10.0.0.1/0	 ---- 	*	 	---- 	*		---- 	ICMP ---- 	2.0% 	 ---- 	1.9%  
Cluster--9	 ---- 	10.0.0.1/0	---- 	10.0.0.2/0	 ---- 	*	 	---- 	*	 	---- 	ICMP ---- 	2.0%  	 ---- 	2.0% 
Cluster--8	 ---- 	10.0.0.3/0	---- 	10.0.0.2/0	 ---- 	*	 	---- 	*		---- 	ICMP ---- 	1.5% 	 ---- 	1.3% 
Cluster--10	 ---- 	10.0.0.2/0	---- 	10.0.0.3/0	 ---- 	*	 	---- 	*		---- 	ICMP ---- 	1.5% 	 ---- 	1.4% 

Clustering Threshold: 1.0%
Total Number of Packets: 120542 
Total Traffic: 123 MB 
 

 