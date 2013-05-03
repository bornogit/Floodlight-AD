package net.floodlightcontroller.anomalydetector;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;



import org.openflow.protocol.OFMatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.floodlightcontroller.anomalydetector.StatCollector.StatResult;
import net.floodlightcontroller.anomalydetector.TrafficCluster.TrafficType;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;



public class DetectionUnit
{
	public  Map<Long, TrafficCluster> UniqueClusters = new HashMap<Long, TrafficCluster>();
	public Map<Long, TrafficCluster> BaseClusters = new HashMap<Long, TrafficCluster>();
	
	public List<StatResult> ClusterStats = new ArrayList<StatResult>();
	
	
	
	private long  TotalPacketCount;
	private double  TotalByteCount;
	public long ClusterID=0;
	public long BaseID = 0;
	
	
	public RuleMaker RuleManager;
	
	protected StatCollector FlowLogger;
	
	public Boolean IsMonitoring;
	private IOFSwitch sw;
	
	protected volatile Thread ThreadStatCollector;
	protected volatile Thread ThreadAnomalyDetector;
	protected volatile Thread ThreadReportGenerator;
	
	//All in milliseconds
	private static final int DetectionInterval = 10000 ;
	private static final int StatCollectionInterval = 10000;
	private static final int ReportGenerationInterval = 10000; // Set it to 1 minute. CHange for testing
	
	//Variables for File Operations
	private PrintWriter LogWriter = null;
	private String FileName;
	protected static String OUTPUT_FILE_NAME = "AD-Log"; 
	protected static String HEADER = "Cluster Label \t ---- \t Source IP \t ---- Destination IP \t ---- \t Source Port \t ---- \t Destination Port ---- \t Protocol \t ---- \t" +
			"PacketCount(%) \t ---- \t ByteCount(%) \n" ;
	
	protected IFloodlightProviderService FloodlightProvider;
	protected static Logger Logger = LoggerFactory.getLogger(RuleMaker.class);
	public DetectionUnit(IOFSwitch sw, IFloodlightProviderService FloodlightProvider)
	{
		
		this.TotalByteCount=0;
		this.TotalPacketCount=0;
		this.sw = sw;
		this.IsMonitoring = true;
		this.ClusterID = 0;
		this.FloodlightProvider = FloodlightProvider;
		
		this.RuleManager = new RuleMaker(this.FloodlightProvider, this);
		this.InitiateBaseClusters();
		this.StartMonitoring();
	}
	
	private void InitiateBaseClusters()
	{
		this.AddBaseClusters(new int[]{-1,4},new int[]{-1,4}, new short[]{-1}, new short[]{-1}, TrafficType.ALL); //Total Traffic
		this.AddBaseClusters(new int[]{-1,4},new int[]{-1,4},new short[]{-1}, new short[]{-1}, TrafficType.TCP); //  All TCP Traffic
		this.AddBaseClusters(new int[]{-1,4},new int[]{-1,4}, new short[]{-1}, new short[]{-1}, TrafficType.UDP); // All UDP Traffic
		this.AddBaseClusters(new int[]{-1,4},new int[]{-1,4}, new short[]{-1}, new short[]{-1}, TrafficType.ICMP); // All Ping Traffic
		this.AddBaseClusters(new int[]{-1,4},new int[]{-1,4}, new short[]{-1}, new short[]{80}, TrafficType.TCP); // All incoming traffic to Port 80
		this.AddBaseClusters(new int[]{-1,4},new int[]{-1,4}, new short[]{80}, new short[]{-2, 6001, 12000}, TrafficType.TCP); // From 80 to High
		this.AddBaseClusters(new int[]{-1,4},new int[]{-1,4},new short[]{-2, 0, 6000}, new short[]{-2, 6001, 12000}, TrafficType.TCP); //  From low port to high port
		this.AddBaseClusters(new int[]{-1,4},new int[]{-1,4}, new short[]{-2, 6001, 12000},new short[]{-2, 0, 6000}, TrafficType.TCP); //  From high port to low port
		this.AddBaseClusters(new int[]{-1,4},new int[]{-1,4}, new short[]{-2, 6001, 12000},new short[]{-2, 6001, 12000}, TrafficType.TCP); //  From high port to high port
		this.AddBaseClusters(new int[]{-1,4},new int[]{-1,4}, new short[]{-1},new short[]{-2, 6001, 12000}, TrafficType.TCP); //  From any port to high port
		
		// need to come up with base rules. 
		
	}
	
	
	private void AddBaseClusters(int[] SrcInfo, int[] DstInfo, short[] SrcPorts, short[] DstPorts, TrafficType Protocol)
	{
		TrafficCluster NewBaseCluster;
		NewBaseCluster = new TrafficCluster(SrcInfo ,DstInfo,SrcPorts,DstPorts,Protocol, this.BaseID);
		BaseClusters.put(NewBaseCluster.ClusterID, NewBaseCluster);
		this.BaseID++;
	}
	
	
	
	
	public void FindParentClusters(TrafficCluster TCluster)
	{
		Iterator<Entry<Long, TrafficCluster>> ClusterIterator = BaseClusters.entrySet().iterator();
		TrafficCluster TempBaseCluster;
		while (ClusterIterator.hasNext())
		{
			boolean IsParent = false;
			Map.Entry<Long, TrafficCluster> BaseClusterEntry = (Map.Entry<Long, TrafficCluster>)ClusterIterator.next();
			TempBaseCluster = BaseClusterEntry.getValue();
			IsParent = TrafficCluster.CompareTwoNwAddr(TempBaseCluster.MatchOnSrcIP, TempBaseCluster.SrcIPMatch, TempBaseCluster.SrcMask, TCluster.SrcIPMatch) 
					&& TrafficCluster.CompareTwoNwAddr(TempBaseCluster.MatchOnDstIP, TempBaseCluster.DstIPMatch, TempBaseCluster.DstMask, TCluster.DstIPMatch)
					&& TrafficCluster.CheckPortMatches(TempBaseCluster, TCluster.SrcPort, TCluster.DstPort)
					&& TrafficCluster.CheckProtocolMatches(TempBaseCluster.MatchOnProtocol, TempBaseCluster.Protocol, TCluster.Protocol); 

			if (IsParent == true)
			{
				TCluster.ParentClusterIDs.add(TempBaseCluster.ClusterID);
			}
			
		}
	}
	
	public void CopyFromCluster(TrafficCluster TCluster)
	{
		if (TCluster.AddedToBase == false)
		{
			TrafficCluster NewBase = new TrafficCluster(new int[]{TCluster.SrcIPMatch, 4}, 
		    				  new int[]{TCluster.DstIPMatch, 4}, 
							  new short[]{TCluster.SrcPort},
							  new short[]{TCluster.DstPort},
							  TCluster.Protocol, 
							  this.BaseID);
			BaseClusters.put(NewBase.ClusterID, NewBase);
			TCluster.AddedToBase = true;
			TCluster.ParentClusterIDs.add(NewBase.ClusterID);
			this.BaseID++;
		}
	}
	
	public void AddCluster(OFMatch Match)
	{
		TrafficCluster TempCluster = new TrafficCluster(Match, this.ClusterID);
		if (!(UniqueClusters.containsValue(TempCluster)))
		{
			this.FindParentClusters(TempCluster);
			UniqueClusters.put(TempCluster.ClusterID, TempCluster);
			this.ClusterID++;
		}
	}
	
	private void InitBaseClusterCt(List<Long> BaseIDs, long PacketCount, double ByteCount)
	{
		for (int i = 0; i<BaseIDs.size(); i++)
		{
			BaseClusters.get(BaseIDs.get(i)).UpdateBaseClusterCount(PacketCount, ByteCount);
		}
	}
	
	private void FinishBaseClusterCt()
	{
		Iterator<Entry<Long, TrafficCluster>> ClusterIterator = BaseClusters.entrySet().iterator();
		TrafficCluster TempCluster;
		while (ClusterIterator.hasNext())
		{
			Map.Entry<Long, TrafficCluster> Cluster = (Map.Entry<Long, TrafficCluster>)ClusterIterator.next();
			TempCluster = Cluster.getValue();
			TempCluster.AdjustBaseClusterCount();
			if ((this.TotalPacketCount > 0) && (this.TotalByteCount > 0))
			{
				TempCluster.CalculateContribution(this.TotalPacketCount, this.TotalByteCount);
			}
		}
	}
	
	private void UpdateClusterStat()
	{
		
		TrafficCluster VolatileCluster; 
		long TempTotalPacketCount = 0;
		double TempTotalByteCount = 0.0;
		for (StatResult result: this.ClusterStats)
		{
			VolatileCluster = UniqueClusters.get(result.ClusterID);
			if (VolatileCluster != null)
			{
				TempTotalPacketCount += result.PacketCount;
				TempTotalByteCount += result.ByteCount;
				VolatileCluster.UpdateCount(result.PacketCount, result.ByteCount);
				InitBaseClusterCt(VolatileCluster.ParentClusterIDs, result.PacketCount, result.ByteCount);
			}
			else
			{
				System.out.println("SOMETHING WENT WRONG");
				break;
			}
			
		}
		this.ClusterStats.clear();
		this.TotalPacketCount = TempTotalPacketCount;
		this.TotalByteCount = TempTotalByteCount;
		this.FinishBaseClusterCt();
		
		// doing a second loop to update the contribution of each cluster relative the so far total counts
		// Will see if we can skip this second loop
		if ((this.TotalPacketCount > 0) && (this.TotalByteCount > 0))
		{
			Iterator<Entry<Long, TrafficCluster>> ClusterIterator = UniqueClusters.entrySet().iterator();
			TrafficCluster TempCluster;
			while (ClusterIterator.hasNext())
			{
				Map.Entry<Long, TrafficCluster> Cluster = (Map.Entry<Long, TrafficCluster>)ClusterIterator.next();
				TempCluster = Cluster.getValue();
				TempCluster.CalculateContribution(this.TotalPacketCount, this.TotalByteCount);
				if (TempCluster.IsBaseType == true)
				{
					this.CopyFromCluster(TempCluster);
				}
			}
		}
	}
	public double GetTotalByteCount() 
	{
		double ByteCount = this.TotalByteCount/1024;
		return (double)Math.round(ByteCount * 1000) / 1000;  // Converting to MB from KB
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
					Iterator<Entry<Long, TrafficCluster>> ClusterIterator = BaseClusters.entrySet().iterator();
					TrafficCluster VolatileCluster;
					String result;
					while (ClusterIterator.hasNext())
					{
						Map.Entry<Long, TrafficCluster> Cluster = (Map.Entry<Long, TrafficCluster>)ClusterIterator.next();
						VolatileCluster = Cluster.getValue();
						if (VolatileCluster.DoPrint == true)
						{
							result = VolatileCluster.GetClusterLabel() + "\t ---- \t" 
									+ VolatileCluster.GetSrcIP() +"\t ---- \t"
									+ VolatileCluster.GetDstIP() + "\t ---- \t" 
									+ VolatileCluster.GetSrcPort() + "\t ---- \t" 
									+ VolatileCluster.GetDstPort() + "\t ---- \t" 
									+ VolatileCluster.Protocol + "\t ---- \t" 
									+ VolatileCluster.GetTotalPacketContribution() + "% \t ---- \t"
									+ VolatileCluster.GetTotalByteContribution() + "% \n";
							LogWriter.append(result);
						}
					}
					result = " Total Number of Packets: " + TotalPacketCount + " Total Traffic: " + GetTotalByteCount() + " MB \n";
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
	
	/* the following function is not used for this approach 2 , but can make this useful for the pure online approach 1 */
	private void StartDetectingAnomaly()
	{
		ThreadAnomalyDetector = new Thread(new Runnable()
		{
			public void run()
			{
				while(IsMonitoring)
				{
					
					Iterator<Entry<Long, TrafficCluster>> ClusterIterator = UniqueClusters.entrySet().iterator();
					//TrafficCluster VolatileCluster; 
					while (ClusterIterator.hasNext())
					{
						/*Map.Entry<Long, TrafficCluster> Cluster = (Map.Entry<Long, TrafficCluster>)ClusterIterator.next();
						VolatileCluster = Cluster.getValue();
						if (VolatileCluster.TotalByteContribution >= DetectionUnit.TrafficThreshold)
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
