# IDS Report
An IDS system using snort, sflow, netflow, elasticsearch and spark

## Technologies/software used in this system:
### Packet capturing and forwarding
- PulledPork 
- Snort IDS 
- barnyard
- hsflowd(sflow host)
- fprobe(netflow host)
- sflowtool(sflow collector)

### Data storing, manipulation and visualization:
- Elasticsearch
- Kibana
- Logstash
- Spark with support for Elasticsearch/Hadoop


## Implementation:
My implementation of this system consists of using 4 virtual machines, all running Ubuntu 16.04, which, for the sake of simplicity, have the following names and functions:
- curious2 (this is a virtual machine placed on the outside segment of the network and is used for capturing/forwarding of sflow packets, capturing/forwarding netflow packets and Snort detection)<br>
Has the following software installed:<br>
PulledPork, Snort, Barnyard, HSFlowD, FProbe
- snortx (same as curious2, but on the insidesegment)<br>
Has the following software installed:<br>
PulledPork, Snort, Barnyard, HSFlowD, FProbe
- collector (used for forwarding of sflows to eshog)<br>
Has the following software installed:<br>
SFlowTool
- eshog (virtual machine for data storing, manipulation, visualization)<br>
Has the following software installed:<br>
ElasticSearch, Logstash, Kibana, Nginx, Spark w/ ElasticSearch

In the following sections, I will describe what I did on a specific Virtual Machine.


## Virtual machine curious2:

I installed snort, barnyard and pulledpork with the help of the following guide: https://www.snort.org/documents <br>
The installation is pretty straight forward and didn't cause many problems. 
Snort is an open source IDS(Intrusion Detection System) that is performing real-time traffic analysis and packet logging. Snort uses rules to detect possible attacks and saves the logs of these possible attacks to files. Rules are obtained with a program called PulledPork that automatically downloads the rules and saves them. These rules are then read by Snort IDS and used for analysis and detection. I needed to create a Snort account in order to get a so called "Oinkcode", which takes care of authentication. I also added a crontab entry in Linux, so that these rules are automatically updated every day and we get the latest rules. <br>
Barnyard2 is an open source interpreter for Snort unified2 binary output files. Its primary use is allowing Snort to write to disk in an efficient manner and leaving the task of parsing binary data into various formats to a separate process that will not cause Snort to miss network traffic. In my case, I configured Barnyard to output the data to a syslog collector, listening on the virtual machine "eshog", instead of just saving events to a local mysql database. 

