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

# ICMP tester
This is a java program, written for the purpose of getting to know the basics of reading, writing,... from/to elasticsearch with spark. It reads ICMP events from today's index, counts them, and if there is more than THRESHOLD of ICMP packets, it writes an event to index "threat". <br>
The "syslog" data(generated by SnortIDS) is stored in ElasticSearch in seperate indexes for each day of storing, meaning, an index: "syslog-2017.07.27" represents all the data, that was stored on 2017.07.27. Each event looks something like this:<br>
```
date:August 29th 2017, 02:00:00.000 Priority:2 message:<68> 2017-08-29T07:11:51Z snortIdsSnortx [129:12:1] stream5: TCP Small Segment Threshold Exceeded [Classification: Potentially Bad Traffic] [Priority: 2]: {TCP} 221.194.47.242:35698 -> 193.138.1.29:22 type:syslog classification: Potentially Bad Traffic unknown:129:12:1 source_ip:221.194.47.242 tags:grok_successful priority_number:68 protocol:TCP @timestamp:August 29th 2017, 09:11:51.841 source_port:35698 dest_ip:193.138.1.29 @version:1 host:193.138.1.29 time:07:11:51 event:stream5: TCP Small Segment Threshold Exceeded dest_port:22 sensor_name:snortIdsSnortx _id:AV4s1QYpKns342lps04p _type:syslog _index:syslog-2017.08.29 _score: -
```
All events have the same fields(date, message,...). We use the field "classification" to get the information on what type of an event occured and field "@timestamp" for the event time.<br>

We run our java program with the following command, where the last argument(5) is the number of ICMP events that trigger the write to elasticsearch method:
```
sudo ./bin/spark-submit --driver-class-path=/home/klemen/elasticsearch-hadoop-5.5.1/dist/elasticsearch-spark-20_2.11-5.5.1.jar --class IDSJava /home/klemen/IDSJava.jar 5
```
## IDSJava.java
```
int THRESHOLD = Integer.parseInt(args[0]);
SparkConf conf = new SparkConf().setAppName("myApp").setMaster("local");
conf.set("es.index.auto.create", "true");
JavaSparkContext jsc = new JavaSparkContext(conf);


//perform ICMP tests, if there are more than THRESHOLD ICMP events, writes a warning back to elasticsearch
ICMPTesting(THRESHOLD, jsc);
```
In this section we initialize Spark configuration, JavaSpark context and allow spark to create an index, if one doesn't exists. We then run the method ICMPTesting with THRESHOLD and JavaSpark context arguments, where THRESHOLD is the number we entered when running this program.<br>

```
private static void ICMPTesting(int THRESHOLD, JavaSparkContext jsc) {

        JavaRDD<Map<String, Object>> esRDD = JavaEsSpark.esRDD(jsc, getCurrentDate(true) + "/syslog").values().filter(doc -> doc.containsValue(" Generic ICMP event"));

        long lastCheck = getLastCheck();
        List<Map<String, Object>> ICMPevents = getOnlyICMPEvents(esRDD, lastCheck);

        if (ICMPevents.size() > THRESHOLD){
            writeEventToES(ICMPevents, jsc, THRESHOLD);
        }
        updateLastCheck();
    }
```
```
    public static Object[] getOnlyICMPEvents(JavaRDD<Map<String, Object>> esRDD1, long lastCheck){
    
        SimpleDateFormat sdf = new SimpleDateFormat("MMM d yyyy HH:mm:ss");
        List<Map<String, Object>> onlyICMPevents = new ArrayList<>();
        try {
            for (Map<String, Object> a : esRDD.collect()) {
                String[] date = a.get("@timestamp").toString().split(" ");
                String time = date[3];
                String month = date[1];
                String day = date[2];
                String year = date[5];
                String wholeDate = String.format("%s %s %s %s",month, day, year, time );
                Date d = sdf.parse(wholeDate);
                if (d.getTime() > lastCheck){
                    onlyICMPevents.add(a);
                }
            }
        } catch (Exception e){
            e.printStackTrace();
        }
        return onlyICMPevents;
    }
```
In method getOnlyICMPEvents(), we create JavaRDD, which stands for Java Resilient Distributed Datasets. It connects to elasticsearch's index syslog-currentDate/syslog and filters out all the events, that dont have " Generic ICMP event" in them. Then, we call the method getOnlyICMPEvents() that returns just the ICMP events, that occured after the last time we ran this program(it reads it from a file). After that, it checks if the number of ICMP events is greater that the threshold value we entered, and if it is, runs the writeEventToEs() method. It also saves the current time in miliseconds to a file, that we can use the next time we run this program.

```
    private static void writeEventToES(List<Map<String, Object>> ICMPevents, JavaSparkContext jsc, int THRESHOLD) {
        System.out.println("Writing events to Elasticsearch.");
        jsc.close();
        SparkConf confSave = new SparkConf().setAppName("myApp").setMaster("local");
        confSave.set("es.index.auto.create", "true");
        JavaSparkContext jscSave = new JavaSparkContext(confSave);

        Map<String, ?> event = ImmutableMap.of("event","The number of ICMP events from the last check exceeded the specified threshold(" + THRESHOLD + ")", "ICMPcount", ICMPevents.size()+"", "date", getCurrentDate(false) + "");

        JavaRDD<Map<String, ?>> javaRDD = jscSave.parallelize(ImmutableList.of(event));
        JavaEsSpark.saveToEs(javaRDD, "threats/icmp");
    }
```
In this method, we close the JavaSpark context we created earlier, since Spark doesn't allow 2 contextes at the same time (I dont know if this is the correct way to do this, but its the only way I could make it work). We create a new context and an event Map with the event info. Next, we make an JavaRDD from our event and save it to ElasticSearch in index "threats" and type "icmp". 


