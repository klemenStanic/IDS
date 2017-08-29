import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.apache.spark.SparkConf;
import org.apache.spark.api.java.JavaPairRDD;
import org.apache.spark.api.java.JavaRDD;
import org.apache.spark.api.java.JavaSparkContext;
import org.elasticsearch.spark.rdd.api.java.JavaEsSpark;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.*;




public class IDSJava {
    public Long lastCheckTime;
    public static void main(String[] args) {
        int THRESHOLD = Integer.parseInt(args[0]);
        SparkConf conf = new SparkConf().setAppName("myApp").setMaster("local");
        conf.set("es.index.auto.create", "true");
        System.out.println("GET CURRENT DATE: " + getCurrentDate(true));
        JavaSparkContext jsc = new JavaSparkContext(conf);


        //perform ICMP tests, if there are more than THRESHOLD ICMP events, writes a warning back to elasticsearch
        ICMPTesting(THRESHOLD, jsc);

    }

    // checks  for ICMP events in Elasticsearch, if more than THRESHOLD, calls writeEventToES()
    private static void ICMPTesting(int THRESHOLD, JavaSparkContext jsc) {
        
        JavaRDD<Map<String, Object>> esRDD = JavaEsSpark.esRDD(jsc, getCurrentDate(true) + "/syslog").values().filter(doc -> doc.containsValue(" Generic ICMP event"));

        long lastCheck = getLastCheck();
        List<Map<String, Object>> ICMPevents = getOnlyICMPEvents(esRDD, lastCheck);

        if (ICMPevents.size() > THRESHOLD){
            writeEventToES(ICMPevents, jsc, THRESHOLD);
        }
        updateLastCheck();
    }

    // writes an ICMP warning to ElasticSearch
    private static void writeEventToES(List<Map<String, Object>> ICMPevents, JavaSparkContext jsc, int THRESHOLD) {
        System.out.println("Writing events to Elasticsearch.");
        jsc.close();
        SparkConf confSave = new SparkConf().setAppName("myApp").setMaster("local");
        confSave.set("es.index.auto.create", "true");
        JavaSparkContext jscSave = new JavaSparkContext(confSave);

        Map<String, ?> numbers = ImmutableMap.of("event","The number of ICMP events from the last check exceeded the specified threshold(" + THRESHOLD + ")", "ICMPcount", ICMPevents.size()+"", "date", getCurrentDate(false) + "");

        JavaRDD<Map<String, ?>> javaRDD = jscSave.parallelize(ImmutableList.of(numbers));
        JavaEsSpark.saveToEs(javaRDD, "threats/icmp");
    }

    // writes the last ICMP checked to file, to know from where to read in next iteration of running this program
    private static void updateLastCheck() {
        try {
            String nowInms = getCurrentDate(false);
            File file = new File("last_check.txt");
            file.delete();
            FileWriter fw = new FileWriter(new File("last_check.txt"), false);
            fw.write(nowInms + "");
            fw.close();
        } catch (Exception e) {
            e.printStackTrace();
        }


    }

    // called by ICMPTesting()
    public static List<Map<String, Object>> getOnlyICMPEvents(JavaRDD<Map<String, Object>> esRDD, long lastCheck){
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

        for (Map<String, Object> a : onlyICMPevents){
            System.out.println(a.get("@timestamp") + "");
        }
        return onlyICMPevents;
    }

    // if boolean full == true; returns full name of the index, else returns @String time in miliseconds
    public static String getCurrentDate(boolean full){
        Calendar now = Calendar.getInstance();
        int day = now.get(Calendar.DAY_OF_MONTH);
        int month = now.get(Calendar.MONTH) + 1;
        int year = now.get(Calendar.YEAR);
        if (full) {
            return "syslog-" + year + "." + String.format("%02d", month) + "." + String.format("%02d", day);
        } else return now.getTimeInMillis() + "";
    }

    // reads time from file. Time = when the last iteration of this program was performed, so we dont need to check the whole index every time we run this program
    public static long getLastCheck() {
        try {
            Scanner sc = new Scanner(new File("last_check.txt"));
            Long time = sc.nextLong();
            sc.close();
            return time;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return 0;
    }
}
