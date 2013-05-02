package net.floodlightcontroller.anomalydetector;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;



import com.google.gson.JsonObject;
import com.google.gson.JsonParser;



public class StatCollector 
{
	private URL TargetURL = null;
	private HttpURLConnection conn = null;
	private BufferedReader BufferReader = null;
	
		
	//Declare the constants
	
	protected static String STAT_FORMAT = "/json";
		
	protected static String ControllerSocket = "localhost:8080";
	protected static String ServiceURI = "/wm/core/switch/";  
	protected static String HTTP_GET = "GET";
	
	
	
	private String StatType;
	private  String StringURL;
	private String SwitchDPID;
	/*Constructor for collecting "statType" parameter from each switch denoted by "dpid" */
	public StatCollector(String dpid, String StatType) 
	{
		 this.StatType = "/" + StatType + "/";
		 this.StringURL =  "http://" + StatCollector.ControllerSocket + StatCollector.ServiceURI + dpid + this.StatType +StatCollector.STAT_FORMAT;
		 
		 this.SwitchDPID = dpid;
	}
	
	
	
	public List<StatResult> GetStats()
	{
		try 
		{
			 this.TargetURL = new URL(this.StringURL);
			 this.conn = (HttpURLConnection) TargetURL.openConnection();
			 if (this.conn != null)
			 {
				 this.conn.setRequestMethod(StatCollector.HTTP_GET); 
				 this.conn.setRequestProperty("Accept", "application/json");
				 if (conn.getResponseCode() != 200) 
				 {
					throw new RuntimeException("Failed : HTTP error code : " + this.conn.getResponseCode());
				 }
				 else
				 {
					return this.ParseLogResponse(this.conn.getInputStream()); 
				 }
			 }
		}
		catch (Exception e) 
		{
			 e.printStackTrace();
		}
		return new ArrayList<StatResult>(); // for now return an empty list in error
	}
	
	
	private List<StatResult> ParseLogResponse(InputStream RestReply)
	{
		String RestReplyString;
		String[] FlowStats;
		String FlowStatsString;
		BufferReader = new BufferedReader(new InputStreamReader(RestReply));
		JsonParser JsonReplyParser = new JsonParser();
		JsonObject JsonReplyObj;
		List<StatResult> StatResults = new ArrayList<StatResult>();
		
		try 
		{
				RestReplyString = BufferReader.readLine(); 
				JsonReplyObj = JsonReplyParser.parse(RestReplyString).getAsJsonObject();
				FlowStatsString = JsonReplyObj.get(this.SwitchDPID).toString();
				StatResult TempResult;
				if (FlowStatsString.length()>2)
				{
					FlowStatsString = FlowStatsString.substring(1, FlowStatsString.length()-1);
					FlowStatsString = FlowStatsString.replaceAll("\\},\\{", "\\}BREAK\\{");
					FlowStats = FlowStatsString.split("BREAK");
					for (int j = 0; j<FlowStats.length; j++)
					{
						TempResult = new StatResult();
						String FlowStat = FlowStats[j];
						JsonReplyObj = JsonReplyParser.parse(FlowStat).getAsJsonObject();
						TempResult.ClusterID = Long.valueOf(JsonReplyObj.get("cookie").toString());
						TempResult.PacketCount = JsonReplyObj.get("packetCount").getAsLong();
						TempResult.ByteCount = JsonReplyObj.get("byteCount").getAsDouble()/1024;
						StatResults.add(TempResult);
					}
				}
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
		}
		
		return StatResults;
	}
	
		
	public class StatResult
	{
		public long ClusterID;
		public long PacketCount;
		public double ByteCount;

	}
 
}
 
