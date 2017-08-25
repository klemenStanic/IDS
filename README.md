# IDS Report
The basic idea is to create an IDS(Intrusion Detection System), that would capture data from the network and save this data to data stash, in our case Elasticsearch. Then, some computations/algorithms would be run on this data to detect unusual occurrences, possible attacks and just plain statistics of the traffic. <br>
Firstly, I tried to install and configure <b>Hogzilla</b>(http://ids-hogzilla.org/), which is an open-source project that provides network anomaly detection and gives some visibility of the network. It comes in two variations, first one is using "Snort" module, the second one is using "sflow" packets for detection. I tried configuring both, but met with little success, because of many problems with installing all the software + very little visibility to what the system is actually doing. <br>

The idea behind configuring Hogzilla was to learn how it is working, so we could use the knowledge to build a similar system. <br>
Basically, "Hogzilla with sflow support" captures sFlows, saves them to HBase, runs some algoritms with Apache Spark and saves events back to HBase. Then, it uses a script to read the generated events and saves them to a local mysql server. The data on mySQL server is used to visualize the events using GrayLog. <br>
This is very similar to what we are trying to accomplish, but with some modifications: instead of using Hbase we use ElasticSearch, Kibana is used as a substitute for GrayLog, so we dont need an mySQL server and can visualize directly from ElasticSearch. Also, we capture network data from multiple sources, so we can compare the traffic on multiple points of interest, and the data we capture isn't just sflow packets, but also netflows and events generated with SnortIDS. This way, we have more data to work with.

## Technologies/software used in this system:
### Packet capturing and forwarding
- PulledPork (https://github.com/shirkdog/pulledpork)
- Snort IDS (https://www.snort.org/)
- barnyard (https://github.com/firnsy/barnyard2)
- hsflowd(sflow host) (https://github.com/sflow/host-sflow)
- fprobe(netflow host) (http://manpages.ubuntu.com/manpages/xenial/man8/fprobe.8.html)
- sflowtool(sflow collector) (https://github.com/sflow/sflowtool)

### Data storing, manipulation and visualization:
- Elasticsearch (https://www.elastic.co/products/elasticsearch)
- Kibana (https://www.elastic.co/products/kibana)
- Logstash (https://www.elastic.co/products/logstash)
- Spark with support for Elasticsearch/Hadoop (https://spark.apache.org/)


## Implementation:
My implementation of this system consists of using 4 virtual machines, all running Ubuntu 16.04, which, for the sake of simplicity, have the following names:
- <b>curious2</b> (this is a virtual machine placed on the outside segment of the network and is used for capturing/forwarding of sflow packets, capturing/forwarding netflow packets and Snort detection)<br>
Has the following software installed:<br>
PulledPork, Snort, Barnyard, HSFlowD, FProbe
- <b>snortx</b> (same as curious2, but on the inside segment)<br>
Has the following software installed:<br>
PulledPork, Snort, Barnyard, HSFlowD, FProbe
- <b>collector</b> (used for forwarding of sflows to eshog)<br>
Has the following software installed:<br>
SFlowTool
- <b>eshog</b> (virtual machine for data storing, manipulation, visualization)<br>
Has the following software installed:<br>
ElasticSearch, Logstash, Kibana, Nginx, Spark w/ ElasticSearch

![alt text](https://github.com/klemenStanic/IDS/blob/master/img/myIDSOverview.jpg)

The VM "curious2" is placed on the outside segment, while all the other VMs are behind a firewall. This way, we can capture network traffic both inside and outside and compare the traffic.

In the following sections, I will describe how I configured every VM.


## Virtual machines "curious2" and "snortx":
I installed snort, barnyard and pulledpork with the help of the following guide: https://www.snort.org/documents <br>
The installation is pretty straight forward and didn't cause many problems. <br>
<b>Snort</b> is an open source IDS(Intrusion Detection System) that is performing real-time traffic analysis and packet logging. Snort uses rules to detect possible attacks and saves the logs of these possible attacks to unified2 (binary) files.<br>
Rules are obtained with a program called <b>PulledPork</b> that automatically downloads the rules and saves them. These rules are then read by Snort IDS and used for analysis and detection. I needed to create a Snort account in order to get a so called "Oinkcode", which takes care of authentication. I also added a crontab entry in Linux, so that these rules are automatically updated every day and we get the latest rules. <br>
<b>Barnyard2</b> is an open source interpreter for Snort unified2 binary output files. Its primary use is allowing Snort to write to disk in an efficient manner and leaving the task of parsing binary data into various formats to a separate process that will not cause Snort to miss network traffic. In my case, I configured Barnyard to output the data to a syslog collector, listening on the virtual machine "eshog", instead of just saving events to a local mysql database. 
<b>Fprobe</b> is a netflow probe, that collects data traffic and emit it as Netflow flows towards the specified collector.<br>
(only on "curious2")<b>Hsflowd</b> stands for Host sflow daemon, which is an open source project that is used for capturing the sflow packets and forwarding them to collectors. It needed to be configured, like shown here: http://sflow.net/host-sflow-linux-config.php. My /etc/hsflowd.conf where ### represents collector/"eshog" VM's IP address:
```
sflow {
    collector {
        ip=###
        udpport=6343
    }
    pcap { dev = eth0 }
}

```

## Virtual machine "collector":
Is used just to forward the sflow packets from router/switch and "curious2" VM to "eshog", using sflowtool.
<b>sflowtool</b> is a sflow collector, that can either print in ASCII or forward the sflows to another collector. <br>
This VM also contains the full <b>Hogzilla IDS</b>, which is currently not functional.


## Virtual machine "eshog":
I installed Elasticsearch, Logstash and Kibana using the install guide https://www.elastic.co/start.

This VM is a central piece of the system. It recieves data from multiple sources and stores it in "elasticsearch". <br>
<b>Elasticsearch</b> is an open-source, broadly-distributable, readily-scalable, enterprise-grade search engine. Accessible through an extensive and elaborate API, Elasticsearch can power extremely fast searches that support your data discovery applications. <br>
<b>Logstash</b> is an open source, server-side data processing pipeline that ingests data from a multitude of sources simultaneously, transforms it, and then sends it to a preffered datastash, in our case, Elasticsearch. <br>
To configure Logstash to write/insert data from our sources to Elasticsearch, I used the following configuration (logstash.conf):
```
input {
  udp {
   port => 5544
   type => "syslog"
  }

  pipe {
   type => "sflow"
   command => "sflowtool -l -p 6343"
  }

  udp {
   port => 9995
   codec => netflow {}
   type => netflow
  }
}

filter {
    if [type] == "syslog" {
        grok {
            match => [
                "message" , '\<%{NUMBER:priority_number}\>%{SPACE}(?<date>(.+?(?=T)))T%{TIME:time}Z%{SPACE}%{USERNAME:sensor_name}%{SPACE}\[(?<unknown>(.+?(?=\])))\]%{SPACE}(?<event>(.+?(?=\[)))\[((.+?(?=\:))):(?<classification>(.+?(?=\])))\] \[((.+?(?=\:)))\:%{SPACE}%{NUMBER:Priority}\]\:%{SPACE}\{%{WORD:protocol}\}%{SPACE}%{IPV4:source_ip}\:%{NUMBER:source_port}%{SPACE}->%{SPACE}%{IPV4:dest_ip}\:%{NUMBER:dest_port}'
            ]
	    add_tag => ["grok_successful"]
        }
    }

    if [type] == "sflow" {
	if ([message] =~ "FLOW"){
			
	        grok {
            		match => { "message" => "%{WORD:SampleType},%{IP:sflow.ReporterIP},%{WORD:sflow.inputPort},%{WORD:sflow.outputPort},%{WORD:sflow.srcMAC},%{WORD:sflow.dstMAC},%{WORD:sflow.EtherType},%{NUMBER:sflow.in_vlan},%{NUMBER:sflow.out_vlan},%{USERNAME:sflow.srcIP},%{USERNAME:sflow.dstIP},%{NUMBER:sflow.IPProtocol},%{WORD:sflow.IPTOS},%{WORD:sflow.IPTTL},%{NUMBER:sflow.srcPort},%{NUMBER:sflow.dstPort},%{DATA:sflow.tcpFlags},%{NUMBER:sflow.PacketSize},%{NUMBER:sflow.IPSize},%{NUMBER:sflow.SampleRate}" }
	        add_tag => ["FLOW_PACKET"]
		}
	}
    
	if ([message] =~ "CNTR"){
		grok {
			match => { "message" => "%{WORD:SampleType},%{IP:sflow.ReporterIP},%{NUMBER:sflow.ifIndex},%{NUMBER:sflow.ifType},%{NUMBER:sflow.ifSpeed},%{NUMBER:sflow.ifDirection},%{NUMBER:sflow.ifStatus},%{NUMBER:sflow.ifInOctets},%{NUMBER:sflow.ifInUcastPkts},%{NUMBER:sflow.ifInMulticastPkts},%{NUMBER:sflow.ifInBroadcastPkts},%{NUMBER:sflow.ifInDiscards},%{NUMBER:sflow.ifInErrors},%{NUMBER:sflow.ifInUnknownProtos},%{NUMBER:sflow.ifOutOctets},%{NUMBER:sflow.ifOutUcastPkts},%{NUMBER:sflow.ifOutMulticastPkts},%{NUMBER:sflow.ifOutBroadcastPkts},%{NUMBER:sflow.ifOutDiscards},%{NUMBER:sflow.ifOutErrors},%{NUMBER:sflow.ifPromiscousMode}" }
			add_tag => ["CNTR_PACKET"]
		} 
   	}
    }
}


output {
 if [type] == "syslog" { 
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "syslog-%{+YYYY.MM.dd}"
  }
 }
 if [type] == "sflow" {
   elasticsearch {
    hosts => ["localhost:9200"]
    index => "sflow-%{+YYYY.MM.dd}"
   }
 }
  if [type] == "netflow" {
   elasticsearch {
    hosts => ["localhost:9200"]
    index => "netflow-%{+YYYY.MM.dd}"
   }
 }
}

```
It consists of three parts; input, filter and output. In the input section, I specified three inputs, one for syslogs coming from two VM with "snort" installed, one for sflows and one for netflows. Logstash has no built-in sflow input fields, so I used "sflowtool" to listen for incoming packets and pipe the outputs(line-by-line data) to Logstash.<br>
The data comes throught the input ports in a line-by-line format. To get useful information from these lines I wrote specific filters for every type of input. I used a logstash's "grok" filters(regular expressions), which help you dissect the line into multiple fields, that are then saved into Elasticsearch. 
I used https://grokdebug.herokuapp.com/ for writing "grok" filters, to make it a bit easier and faster.<br>
To save data to the correct Elasticsearch index, I specified 3 outputs, one for syslogs, one for sflows and another one for netflows.

<b>Kibana</b> is a tool used for vizualizing the data stored in Elasticsearch and it provides numerous other functions like time series, analyzing relationships, exploring anomalies with Machine Learing(needs a plugin X-Pack) etc.. <br>
Since Kibana provides a web UI only on a computer we are running it on and we cant get UI over SSH, I used <b>nginx</b> as a reverse proxy to be able to connect to Kibana UI on other machines.
TODO spark



# Commands for starting the individual services on each of the virtual machines:

## Virtual machines "curious2" and "snortx":
```
#starting hsflowd for sflow collection and forwording (only on "curious2", which is on the outside segment, sflows from inside segment are being sent from "collector")
sudo service hsflowd start
#starting snort in daemon mode
sudo /usr/local/bin/snort -q -u snort -g snort -c /etc/snort/snort.conf -i eth0 -D

#starting barnyard in continuous and daemon mode
sudo barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort/ -f snort.u2 -g snort -w /var/log/snort/barnyard2.waldo -D

#starting netflow host and sending data to "eshog" VM
sudo fprobe ###.###.###.###:9995
```
## Virtual machine "collector":
```
#using sflowtool to forward any sflow packets to "eshog" VM
sudo sflowtool -f ###.###.###.###/6343 &
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

