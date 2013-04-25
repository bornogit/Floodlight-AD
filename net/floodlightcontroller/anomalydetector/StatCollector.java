package net.floodlightcontroller.anomalydetector;

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
import java.util.Arrays;
import java.util.StringTokenizer;

import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;



public class StatCollector 
{
	private URL TargetURL = null;
	private HttpURLConnection conn = null;
	private BufferedReader BufferReader = null;
	/*
	 *  Use more unambiguous name e.g. LogWriter instead of log. So that you can have LogWriter and LogFile - two different
	 *  types of objects
	 */
	
	private PrintWriter LogWriter = null;
	private String StatType = null;
	
	private String FileName = null;
	
	//Declare the constants
	protected static String OUTPUT_FILE_NAME = "LogWriter";
	protected static String STAT_FORMAT = "/json";
	
	
	protected static String ControllerSocket = "localhost:8080";
	protected static String ServiceURI = "/wm/core/switch/";  
	protected static String HTTP_POST = "POST";
	protected static String HTTP_GET = "GET";
	protected static String LOG_FORMAT = "<DestIP/subnet NWproto SrcIP/subnet DestPort SrcPort byteCnt pktCnt>";
	private  String StringURL = null;
	/*Constructor for collecting "statType" parameter from each switch denoted by "dpid" */
	public StatCollector(String dpid, String StatType) 
	{
		 this.StatType = "/" + StatType + "/";
		 this.StringURL =  "http://" + StatCollector.ControllerSocket + StatCollector.ServiceURI + dpid + this.StatType + StatCollector.STAT_FORMAT;
		 System.out.println(this.StringURL);
		 this.FileName = StatCollector.OUTPUT_FILE_NAME + "_" + "dpid" + "_" + ".txt";
		 
	}
	
	
	public void Connect()
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
					this.LogResponse(this.conn.getInputStream()); 
				 }
			 }
		}
		catch (Exception e) 
		{
			 e.printStackTrace();
		}
	}
	
	
	private void OpenLogWriter()
	{
		try 
		{
		   LogWriter = new PrintWriter(this.FileName);
		} 
		catch (FileNotFoundException e)
		{
			e.printStackTrace();
		}
	}
	
	private void CloseLogWriter()
	{
		if (this.LogWriter != null)
		{
			try
			{
				this.LogWriter.close();
			}
			catch (Exception e)
			{
				e.printStackTrace();
			}
		}
	}
	
	/*Method to LogWriter the response */
	private void LogResponse(InputStream input)
	{
		String output;
		String parsedOutput;
		JSONObject test; 
		BufferReader = new BufferedReader(new InputStreamReader(input));
		this.OpenLogWriter();
		try 
		{
			
			while ((output = BufferReader.readLine()) != null) 
			{
				output = "{'foo':'bar', 'coolness':2.0, 'altitude':39000, 'pilot':{'firstName':'Buzz',          'lastName':'Aldrin'}, 'mission':'apollo 11'}";
				test = (JSONObject)JSONSerializer.toJSON(output);
				
				//System.out.println(test.get("priority"));
				
				parsedOutput = this.ParseResult(output);
				this.LogWriter.println(StatCollector.LOG_FORMAT);
				this.LogWriter.append(parsedOutput);
			}
			
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
		}
		this.CloseLogWriter();
	}
	
	private String ParseResult(String input)
	{
		String result = "";
		StringTokenizer tokenizer = new StringTokenizer(input, "[ :,\"{}\\[\\]]+");
		while (tokenizer.hasMoreElements()) 
		{
		//System.out.println(tokenizer.nextToken());
			String temp;
			temp = tokenizer.nextToken();
			if(temp.equals("networkDestination"))
			{
				result = result + " <";
				result = result + tokenizer.nextToken();
				result = result + "/";
			}
			
			if(temp.equals("networkDestinationMaskLen"))
			{
				result = result + tokenizer.nextToken();
				result = result + " ";
			}
			
			if(temp.equals("networkProtocol"))
			{
				result = result + tokenizer.nextToken();
				result = result + " ";
			}
			
			if(temp.equals("networkSource"))
			{
				result = result + tokenizer.nextToken();
				result = result + "/";
			}
			
			if(temp.equals("networkSourceMaskLen"))
			{
				result = result + tokenizer.nextToken();
				result = result + " ";
			}
			
			if(temp.equals("transportDestination"))
			{
				result = result + tokenizer.nextToken();
				result = result + " ";
			}
			
			if(temp.equals("transportSource"))
			{
				result = result + tokenizer.nextToken();
				result = result + " ";
			}
			
			if(temp.equals("byteCount"))
			{
				result = result + tokenizer.nextToken();
				result = result + " ";
			}
			
			if(temp.equals("packetCount"))
			{
				result = result + tokenizer.nextToken();
				result = result + "> ";
			}
		}

		
		return result;
	}
	
	private void CloseHttpConn()
	{
		if (this.conn != null)
		{
			try 
			{
				this.conn.disconnect();
			}
			catch (Exception e)
			{
				e.printStackTrace();
			}
		}
		
	}
	
	
 
}
 
