package net.floodlightcontroller.anomalydetection;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
 
public class StatCollector {
 
	private URL TargetURL = null;
	private HttpURLConnection conn = null;
	private BufferedReader br = null;
	private PrintWriter log = null;
	
	
	/*Constructor for collecting "statType" parameter from all switches */
	public StatCollector(String statType)
	{
		 String temp = new String("http://localhost:8080/wm/core/switch/all/");
		 temp = temp + statType + "/json";
		 String filename = new String("log");
		 filename = filename + "_" + "all" + "_" + statType + ".txt";
		 try {
			log = new PrintWriter(filename);
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		}
		 
		 try {
			 this.TargetURL = new URL(temp);
			 this.conn = (HttpURLConnection) TargetURL.openConnection();
			 
		 }
		 catch (MalformedURLException e) {
			 e.printStackTrace();
 
		 } 
		 catch (IOException e) {
			 e.printStackTrace();
		 }
		 
	}
	
	
	/*Constructor for collecting "statType" parameter from each switch denoted by "dpid" */
	public StatCollector(String dpid, String statType) 
	{
		 String temp = new String("http://localhost:8080/wm/core/switch/");
		 temp = temp + dpid + statType + "/json";
		 String filename = new String("log");
		 filename = filename + "_" + dpid + "_" + statType + ".txt";
		 try {
			log = new PrintWriter(filename);
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		}
		 
		 try {
			 this.TargetURL = new URL(temp);
			 this.conn = (HttpURLConnection) TargetURL.openConnection();
			 
		 }
		 catch (MalformedURLException e) {
			 e.printStackTrace();
 
		 } 
		 catch (IOException e) {
			 e.printStackTrace();
		 }
		 
	}
	
	
	/*Method to initialize the "conn" parameter */
	public void InitializeCollector()  
	{
		try {
			conn.setRequestMethod("GET");
			conn.setRequestProperty("Accept", "application/json");
			
			if (conn.getResponseCode() != 200) {
				throw new RuntimeException("Failed : HTTP error code : "
						+ conn.getResponseCode());
			}
		} catch (ProtocolException e) {
			
			e.printStackTrace();
		} catch (IOException e) {
			
			e.printStackTrace();
		}
		
		
	}
	
	/*Method to log the response */
	public void logResponse(InputStream input)
	{
		String output;
		br = new BufferedReader(new InputStreamReader(input));
		try {
			while ((output = br.readLine()) != null) {
				System.out.println(output);
				log.append(output);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		log.close();
	}
	
	
	public void disconnect()
	{
		conn.disconnect();
	}
	  
 
	}
 
