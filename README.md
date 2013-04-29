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

Update April 28 Commit 

1. New Stat Collector
2. New thread management, each operation runs in separate threats
3. Cluster management e.g. Create Cluster, update counts. track flows , etc.
4. Added Learning Switch logic.
5. Generate Report (only the basic one for now)
6. Relate Flow with Clusters 
7. Miscellanious

