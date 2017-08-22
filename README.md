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


## Virtual machines "curious2" and "snortx":
I installed snort, barnyard and pulledpork with the help of the following guide: https://www.snort.org/documents <br>
The installation is pretty straight forward and didn't cause many problems. <br>
<b>Snort</b> is an open source IDS(Intrusion Detection System) that is performing real-time traffic analysis and packet logging. Snort uses rules to detect possible attacks and saves the logs of these possible attacks to unified2 (binary) files.<br>
Rules are obtained with a program called <b>PulledPork</b> that automatically downloads the rules and saves them. These rules are then read by Snort IDS and used for analysis and detection. I needed to create a Snort account in order to get a so called "Oinkcode", which takes care of authentication. I also added a crontab entry in Linux, so that these rules are automatically updated every day and we get the latest rules. <br>
<b>Barnyard2</b> is an open source interpreter for Snort unified2 binary output files. Its primary use is allowing Snort to write to disk in an efficient manner and leaving the task of parsing binary data into various formats to a separate process that will not cause Snort to miss network traffic. In my case, I configured Barnyard to output the data to a syslog collector, listening on the virtual machine "eshog", instead of just saving events to a local mysql database. 
TODO SFLOW, NETFLOW


## Virtual machine "collector":
Is used just to forward the sflow packets from router/switch and "curious2" VM using sflowtool. It also contains the full <b>Hogzilla IDS</b>, which is currently not functional.


## Virtual machine "eshog":
Is a central piece of the system. It recieves data from multiple sources and stores it in "elasticsearch". <br>
<b>Elasticsearch</b> is an open-source, broadly-distributable, readily-scalable, enterprise-grade search engine. Accessible through an extensive and elaborate API, Elasticsearch can power extremely fast searches that support your data discovery applications. <br>
<b>Logstash</b> is an open source, server-side data processing pipeline that ingests data from a multitude of sources simultaneously, transforms it, and then sends it to a preffered datastash, in our case, Elasticsearch. <br>
<b>Kibana</b> is a tool used for vizualizing the data stored in Elasticsearch and it provides numerous other functions like time series, analyzing relationships, exploring anomalies with Machine Learing(needs a plugin X-Pack) etc.. <br>
Since Kibana provides a web UI only on a computer we are running it on and we cant get UI over SSH, I used nginx as a reverse proxy to be able to connect to Kibana UI on other machines.
TODO spark



# Commands for starting the individual services on each of the virtual machines:

## Virtual machines "curious2" and "snortx":
```
#starting snort in daemon mode
sudo /usr/local/bin/snort -q -u snort -g snort -c /etc/snort/snort.conf -i eth0 -D

#starting barnyard in continuous and daemon mode
sudo barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort/ -f snort.u2 -g snort -w /var/log/snort/barnyard2.waldo -D

#starting netflow host and sending data to "eshog" VM
sudo fprobe 193.138.1.30:9995
```
## Virtual machine "collector":
```
#using sflowtool to forward any sflow packets to "eshog" VM
sudo sflowtool -f 192.138.1.30/6343 &
```

## Virtual machine "eshog":
```
#starting elasticsearch
sudo service elasticsearch start

#starting logstash
sudo service logstash start

#starting kibana 
sudo service kibana start

#starting spark-shell with elasticsearch plugin
sudo /usr/local/share/spark/spark-2.0.2/bin/spark-shell --driver-class-path=/home/klemen/elasticsearch-hadoop-5.5.1/dist/elasticsearch-spark-20_2.11-5.5.1.jar
```

