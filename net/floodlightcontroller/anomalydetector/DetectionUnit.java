package net.floodlightcontroller.anomalydetector;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;



import org.openflow.protocol.OFMatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.anomalydetector.StatCollector.StatResult;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;

public class DetectionUnit
{
	public  Map<Long, TrafficCluster> Clusters = new HashMap<Long, TrafficCluster>();
	
	public List<StatResult> ClusterStats = new ArrayList<StatResult>();
	
	
	private long  TotalPacketCount;
	private double  TotalByteCount;
	public int ClusterID=0;

	public static final double CLUSTER_THRESHOLD = 20;
	
	private RuleMaker RuleManager;
	
	protected StatCollector FlowLogger;
	
	public Boolean IsMonitoring;
	private IOFSwitch sw;
	
	protected volatile Thread ThreadStatCollector;
	protected volatile Thread ThreadAnomalyDetector;
	protected volatile Thread ThreadReportGenerator;
	
	//All in milliseconds
	private static final int DetectionInterval = 10000 ;
	private static final int StatCollectionInterval = 10000;
	private static final int ReportGenerationInterval = 60000; // Set it to 1 minute. CHange for testing
	
	//Variables for File Operations
	private PrintWriter LogWriter = null;
	private String FileName;
	protected static String OUTPUT_FILE_NAME = "AD-Log"; 
	protected static String HEADER = "Cluster Label \t ---- \t Source IP \t ---- Destination IP \t ---- \t Source Port \t ---- \t Destination Port ---- \t Protocol \t ---- \t" +
			"PacketCount(%) \t ---- \t ByteCount(%) \n" ;
	
	public DetectionUnit(IOFSwitch sw, IStaticFlowEntryPusherService sfp)
	{

		
		this.TotalByteCount=0;
		this.TotalPacketCount=0;
		this.sw = sw;
		this.IsMonitoring = true;
		this.ClusterID = 0;
		//this.RuleManager = new RuleMaker(sw,sfp);
		//this.InitiateBaseClusters();
		this.StartMonitoring();
	}
	
	private void InitiateBaseClusters()
	{
		TrafficCluster NewBaseCluster;
///		NewBaseCluster = new TrafficCluster(false, "*", "*", "*", "*",TrafficCluster.TrafficType.TCP, this.ClusterID);
		//Clusters.put(NewBaseCluster.ClusterID, NewBaseCluster);
		this.ClusterID++;
		
	}
	
	public void AddCluster(OFMatch Match)
	{
		
		TrafficCluster TempCluster = new TrafficCluster(Match, false,  this.ClusterID);
		Clusters.put(TempCluster.ClusterID, TempCluster);
		this.ClusterID++;
	}
	
	private void UpdateClusterStat()
	{
		
		TrafficCluster VolatileCluster; 
		long TempTotalPacketCount = 0;
		double TempTotalByteCount = 0.0;
		for (StatResult result: this.ClusterStats)
		{
			
			VolatileCluster = Clusters.get(result.ClusterID);
			if (VolatileCluster != null)
			{
				TempTotalPacketCount += result.PacketCount;
				TempTotalByteCount += result.ByteCount;
				VolatileCluster.UpdateCount(result.PacketCount, result.ByteCount);
				
			}
			else
			{
				System.out.println("SOMETHING WENT WRONG");
				break;
			}
			
		}
		this.TotalPacketCount = TempTotalPacketCount;
		this.TotalByteCount = TempTotalByteCount;
		
		this.ClusterStats.clear();
		// doing a second loop to update the contribution of each cluster relative the so far total counts
		// Will see if we can skip this second loop
		if ((this.TotalPacketCount > 0) && (this.TotalByteCount > 0))
		{
			Iterator ClusterIterator = Clusters.entrySet().iterator();
			while (ClusterIterator.hasNext())
			{
				Map.Entry<String, TrafficCluster> Cluster = (Map.Entry<String, TrafficCluster>)ClusterIterator.next();
				Cluster.getValue().CalculateContribution(this.TotalPacketCount, this.TotalByteCount);
			}
		}
	}
	
	
	
	
	public void StartMonitoring()
	{
		this.FlowLogger = new StatCollector(sw.getStringId(), "flow");
		this.StartCollectingStats();
		this.StartDetectingAnomaly();
		this.GenerateClusterReport();
	}
	
	public void StopMonitoring()
	{
		this.IsMonitoring = false;
	}
	
	
	
	private void GenerateClusterReport()
	{
		
		ThreadReportGenerator = new Thread(new Runnable()
		{
			public void run()
			{
				Date CurrentDate = new Date();
				this.OpenLogWriter();
				LogWriter.append("\n" + CurrentDate.getTime() + "\n"); //right now it's returning the milliseconds form epoch .. we can later replace it with proper date time
				LogWriter.append(DetectionUnit.HEADER);
				this.CloseLogWriter();
				while(IsMonitoring)
				{
					this.OpenLogWriter();
					Iterator ClusterIterator = Clusters.entrySet().iterator();
					TrafficCluster VolatileCluster;
					String result;
					while (ClusterIterator.hasNext())
					{
						Map.Entry<String, TrafficCluster> Cluster = (Map.Entry<String, TrafficCluster>)ClusterIterator.next();
						VolatileCluster = Cluster.getValue();
						result = TrafficCluster.ClusterLabel+VolatileCluster.ClusterID + "\t ---- \t" + VolatileCluster.SourceIP +"\t ---- \t"+ 
								VolatileCluster.DestIP+ "\t ---- \t" + VolatileCluster.Protocol + "\t ---- \t" + VolatileCluster.TotalPacketContribution + "% \t ---- \t"
								+ VolatileCluster.TotalByteContribution + "% \n";
						LogWriter.append(result);
					}
					result = "Total Number of Cluster : " + ClusterID + " Total Number of Packets: " + TotalPacketCount + " Total Traffic: " + TotalByteCount/1024 + " MB \n";
					LogWriter.append(result);
					this.CloseLogWriter();
					
					try
					{
						Thread.sleep(DetectionUnit.ReportGenerationInterval);
					}
					catch (Exception e)
					{
						e.printStackTrace();
					}
				}
				this.OpenLogWriter();
			}
			private void OpenLogWriter()
			{
				try 
				{
				   LogWriter = new PrintWriter(new FileWriter(FileName, true));
				 } 
				catch (Exception e)
				{
					e.printStackTrace();
				}
			}
			
			private void CloseLogWriter()
			{
				if (LogWriter != null)
				{
					try
					{
						LogWriter.close();
					}
					catch (Exception e)
					{
						e.printStackTrace();
					}
				}
			}
		});
		
		FileName = DetectionUnit.OUTPUT_FILE_NAME + "_" + sw.getId() + "_" + ".txt";
		ThreadReportGenerator.start();
	}
	
	
	private void StartDetectingAnomaly()
	{
		ThreadAnomalyDetector = new Thread(new Runnable()
		{
			public void run()
			{
				while(IsMonitoring)
				{
					Iterator ClusterIterator = Clusters.entrySet().iterator();
					TrafficCluster VolatileCluster; 
					while (ClusterIterator.hasNext())
					{
						Map.Entry<String, TrafficCluster> Cluster = (Map.Entry<String, TrafficCluster>)ClusterIterator.next();
						VolatileCluster = Cluster.getValue();
						/*if (VolatileCluster.TotalByteContribution >= DetectionUnit.TrafficThreshold)
						{
							VolatileCluster.NeedDPI = true;
							// DPI
						}*/
					}
					try
					{
						Thread.sleep(DetectionUnit.DetectionInterval);
					}
					catch (Exception e)
					{
						e.printStackTrace();
					}
				}
			}
		});
		ThreadAnomalyDetector.start();
		
	}
	
	
	
	private void StartCollectingStats()
	{
		
		ThreadStatCollector = new Thread(new Runnable()
		{
			public void run()
			{
				while(IsMonitoring)
				{	
					try
					{
						ClusterStats=FlowLogger.GetStats();
						UpdateClusterStat();
						Thread.sleep(DetectionUnit.StatCollectionInterval);
					}
					catch(Exception e)
					{
						e.printStackTrace();
					}
				} 
				
			}
		});
		ThreadStatCollector.start();
	}
	
	
}
