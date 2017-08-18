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
My implementation of this system consists of using 4 virtual machines, which, for the sake of simplicity, have the following names and functions:
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


