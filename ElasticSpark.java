import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.apache.spark.SparkConf;
import org.apache.spark.api.java.JavaRDD;
import org.apache.spark.api.java.JavaSparkContext;
import org.elasticsearch.spark.rdd.api.java.JavaEsSpark;

import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ElasticSpark {
    static int THRESHOLD = 0;
    static int TIMEINTERVAL = 0;

    static boolean MORETHANTHRESHOLD = false;
    static String MOSTPACKETSSENTFROM = "";
    static long MOSTPACKETSSENTFROMNUM = 0;
    static long NUMBEROFPACKETS = 0;

    public static void main(String[] args) {
        TIMEINTERVAL = Integer.parseInt(args[0]);
        THRESHOLD = Integer.parseInt(args[1]);

        SparkConf conf = getConfWithQuery(TIMEINTERVAL);
        JavaSparkContext jsc  = new JavaSparkContext(conf);
        JavaRDD<Map<String, Object>> esRDD = JavaEsSpark.esRDD(jsc, "snortevents/syslog").values();
        ICMPTest(esRDD);

        if (MORETHANTHRESHOLD) {
            writeResultsToES(jsc);
        }
    }



    public static SparkConf getConfWithQuery(int secondsSinceLastCheck){
        SparkConf conf = new SparkConf().setAppName("myApp").setMaster("local");
        conf.set("es.resource", "snortevents/syslog");
        conf.set("es.index.auto.create", "true");
        conf.set("es.query", "{\"bool\": {\n" +
                "      \"must\": [\n" +
                "        {\"term\" : {\"classification\" : \" Generic ICMP event\"}},\n" +
                "        {\"range\" : {\"@timestamp\": {\n" +
                "          \"gt\": \"now-" + secondsSinceLastCheck + "s\"\n" +
                "        }}}\n" +
                "      ]\n" +
                "    }}");
        return conf;
    }

    private static void writeResultsToES(JavaSparkContext jsc) {
        System.out.println("Writing events to Elasticsearch.");
        jsc.close();
        SparkConf confSave = new SparkConf().setAppName("myApp").setMaster("local");
        confSave.set("es.index.auto.create", "true");
        JavaSparkContext jscSave = new JavaSparkContext(confSave);

        ImmutableMap<String, ?> writeOut = ImmutableMap.of("event", "The number of ICMP events from the last check exceeded the specified threshold of " + THRESHOLD,
                "ICMPcount", NUMBEROFPACKETS,
                "mostPacketsSentFrom_IP", MOSTPACKETSSENTFROM,
                "mostPacketsSentFrom_Num", MOSTPACKETSSENTFROMNUM,
                "date", getCurrentDate(false));

        JavaRDD<Map<String, ?>> javaRDD = jscSave.parallelize(ImmutableList.of(writeOut));
        JavaEsSpark.saveToEs(javaRDD, "threats/icmp");
        System.out.println("DONE WITH WRITING");
    }

    public static void ICMPTest(JavaRDD<Map<String, Object>> esRDD){
        if (esRDD.count() >= THRESHOLD){
            MORETHANTHRESHOLD = true;
            NUMBEROFPACKETS = (long) esRDD.count();
            System.out.println("THRESHOLD: " + THRESHOLD);
            System.out.println("TIMEINTERVAL: " + TIMEINTERVAL);
            System.out.println("MORETHANTHRESHOLD: " + MORETHANTHRESHOLD);
            System.out.println("NUMBEROFPACKETS: " + NUMBEROFPACKETS);
            System.out.println("classifications: ");
            Map<String, Integer> mostActive = new HashMap<String, Integer>();
            for (Map<String, Object> a : esRDD.collect()){
                String ip = a.get("source_ip") + "";
                if (!mostActive.containsKey(ip)){
                    mostActive.put(ip, 0);
                } else {
                    mostActive.put(ip, mostActive.get(ip) + 1);
                }
            }

            String mostActiveIP = "";
            int mostActiveNum = 0;
            for (String key : mostActive.keySet()){
                if (mostActive.get(key) > mostActiveNum){
                    mostActiveIP = key;
                    mostActiveNum = mostActive.get(key);
                }
            }
            MOSTPACKETSSENTFROM = mostActiveIP;
            MOSTPACKETSSENTFROMNUM = mostActiveNum;

        }
    }

    public static String getCurrentDate(boolean full){
        Calendar now = Calendar.getInstance();
        int day = now.get(Calendar.DAY_OF_MONTH);
        int month = now.get(Calendar.MONTH) + 1;
        int year = now.get(Calendar.YEAR);
        if (full) {
            return "syslog-" + year + "." + String.format("%02d", month) + "." + String.format("%02d", day);
        } else return now.getTimeInMillis() + "";
    }

}
