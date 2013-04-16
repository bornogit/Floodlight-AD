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
	private String StringURL = null;
	private String FileName = null;
	
	//Declare the constants
	protected static String OUTPUT_FILE_NAME = "LogWriter";
	protected static String STAT_FORMAT = "/json";
	// we now have only one switch. But an array will help us extending to work with multiple switches
	protected static String[] SWITCH_SOCKET = {"http://localhost:8080/wm/core/switch/all/"};  
	protected static String HTTP_POST = "POST";
	protected static String HTTP_GET = "GET";
	
	
	/*Constructor for collecting "statType" parameter from all switches */
	public StatCollector(String statType)
	{
		 this.StatType = statType;
		 this.FileName = StatCollector.OUTPUT_FILE_NAME + "_" + "all" + "_" + this.StatType + ".txt";
		 this.StringURL = StatCollector.SWITCH_SOCKET[0] + this.StatType + StatCollector.STAT_FORMAT;
	}
	
		
	/*Constructor for collecting "statType" parameter from each switch denoted by "dpid" */
	public StatCollector(String dpid, String statType) 
	{
		 this.StatType = statType;
		 this.StringURL =  StatCollector.SWITCH_SOCKET[0] + dpid + this.StatType + StatCollector.STAT_FORMAT;
		 this.FileName = StatCollector.OUTPUT_FILE_NAME + "_" + "dpid" + "_" + this.StatType + ".txt";
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
		catch (Exception e) //If we don't the what could go wrong, catch all types of exceptions 
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
		BufferReader = new BufferedReader(new InputStreamReader(input));
		this.OpenLogWriter();
		try 
		{
			while ((output = BufferReader.readLine()) != null) 
			{
				/* 
				 * Commenting out this line. If we are printing on a file, printing on the console at the same time
				 * is unnecessary and it will slow the system down. But please feel free to uncomment it for debugging
				 * System.out.println(output);  
				 * 
				 * */ 
				System.out.println(output); 
				this.LogWriter.append(output);
			}
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
		}
		this.CloseLogWriter();
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
	
	private String ParseResult()
	{
		String ParsedResult="";
		
		return ParsedResult;
	}
 
}
 
