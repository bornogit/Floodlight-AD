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
import net.floodlightcontroller.anomalydetector.TrafficCluster.TrafficType;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.web.serializers.IPv4Serializer;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;

public class DetectionUnit
{
	public  Map<Long, TrafficCluster> Clusters = new HashMap<Long, TrafficCluster>();
	public Map<Integer, BaseCluster> BaseClusters = new HashMap<Integer, BaseCluster>();;
	
	public List<StatResult> ClusterStats = new ArrayList<StatResult>();
	
	
	private long  TotalPacketCount;
	private double  TotalByteCount;
	public long ClusterID=0;
	public int BaseClusterId=0;

	
	
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
	public DetectionUnit(IOFSwitch sw, IFloodlightProviderService FloodlightProvider)
	{
		
		this.TotalByteCount=0;
		this.TotalPacketCount=0;
		this.sw = sw;
		this.IsMonitoring = true;
		this.ClusterID = 0;
		this.FloodlightProvider = FloodlightProvider;
		
		this.RuleManager = new RuleMaker(this.FloodlightProvider, this);
		//this.InitiateBaseClusters();
		this.StartMonitoring();
	}
	
	private void InitiateBaseClusters()
	{
		BaseCluster NewBaseCluster;
				
		NewBaseCluster = new BaseCluster(new int[]{1,2},new int[]{0,1}, new short[]{0, 0, 5000}, TrafficType.TCP, this.BaseClusterId);
		BaseClusters.put(NewBaseCluster.BaseID, NewBaseCluster);
		this.BaseClusterId++;
		
	}
	
	
	
	public static boolean CheckProtocolMatches(boolean MatchOnProtocol, TrafficType BaseProtocol, TrafficType InputProtocol)
	{
		boolean result = false;
		if (MatchOnProtocol == true)
		{
			if (BaseProtocol == InputProtocol)
			{
				result = true;
			}
		}
		else
		{
			result=true;
		}
		return result;
	}
	
	public static boolean CheckPortMatches(BaseCluster Base, short InputSrcPort, short InputDstPort)
	{
		boolean result = false;
		if (Base.MatchOnPortRange == true)
		{
			if ((InputSrcPort >= Base.LowPort) && (InputSrcPort <= Base.HighPort)
				&& (InputDstPort >= Base.LowPort) && (InputDstPort <= Base.HighPort))
			{
				result = true;	
			}
		}
		else if ((Base.MatchOnPortExact == true) && (Base.SrcPort == InputSrcPort) && (Base.DstPort == InputDstPort))
		{
			result = true;
		}
		else
		{
			result = true;
		}
		
		return result;
	}
	
	public static boolean CompareTwoNwAddr(boolean MatchOnSrcIP, int BaseIP, int BaseMask, int InputClusterIP)
	{
		if (MatchOnSrcIP == true)
		{
			byte[] BaseIpByte = IPv4.toIPv4AddressBytes(BaseIP);
			byte[] InputIpByte = IPv4.toIPv4AddressBytes(InputClusterIP);
			byte check = 1;
			for (int i =0 ; i < BaseMask; i++)
			{
				check = (byte)(check & (BaseIpByte[i] ^ InputIpByte[i])) ;
			}
			if (check == 0)
			{
				return true;
			}
			else
			{
				return false;
			}

		}
		else 
		{
			return true;
		}
	}
	
	
	public void AddToBaseCluster(TrafficCluster TCluster)
	{
		Iterator ClusterIterator = BaseClusters.entrySet().iterator();
		BaseCluster TempBaseCluster;
		while (ClusterIterator.hasNext())
		{
			boolean IsParent = false;
			Map.Entry<Integer, BaseCluster> BaseClusterEntry = (Map.Entry<Integer, BaseCluster>)ClusterIterator.next();
			TempBaseCluster = BaseClusterEntry.getValue();
			IsParent = CompareTwoNwAddr(TempBaseCluster.MatchOnSrcIP, TempBaseCluster.SrcIPMatch, TempBaseCluster.SrcMask, TCluster.SourceIP) 
					&& CompareTwoNwAddr(TempBaseCluster.MatchOnDstIP, TempBaseCluster.DstIPMatch, TempBaseCluster.DstMask, TCluster.DestIP)
					&& CheckPortMatches(TempBaseCluster, TCluster.SourcePort, TCluster.DestPort)
					&& CheckProtocolMatches(TempBaseCluster.MatchOnProtocol, TempBaseCluster.Protocol, TCluster.Protocol); 

			if (IsParent == true)
			{
				TCluster.ParentClusterIDs.add(TempBaseCluster.BaseID);
			}
			
		}
	}
	
	public void CopyFromCluster(TrafficCluster TCluster)
	{
		BaseCluster NewBase = new BaseCluster(new int[]{TCluster.SourceIP, 4}, 
										new int[]{TCluster.DestIP, 4}, 
										new short[]{-1, TCluster.SourcePort, TCluster.DestPort}, 
										TCluster.Protocol,this.BaseClusterId);
		BaseClusters.put(NewBase.BaseID, NewBase);
		this.BaseClusterId++;
		
	}
	
	public void AddCluster(OFMatch Match)
	{
		TrafficCluster TempCluster = new TrafficCluster(Match, this.ClusterID);
		this.AddToBaseCluster(TempCluster);
		Clusters.put(TempCluster.ClusterID, TempCluster);
		this.ClusterID++;
	}
	
	private void UpdateBaseCluster(List<Integer> BaseIDs, long PacketCount, double ByteCount)
	{
		for (int i = 0; i<BaseIDs.size(); i++)
		{
			BaseClusters.get(BaseIDs.get(i)).UpdateCount(PacketCount, ByteCount);
		}
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
				UpdateBaseCluster(VolatileCluster.ParentClusterIDs, result.PacketCount, result.ByteCount);
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
			TrafficCluster TempCluster;
			while (ClusterIterator.hasNext())
			{
				Map.Entry<String, TrafficCluster> Cluster = (Map.Entry<String, TrafficCluster>)ClusterIterator.next();
				TempCluster = Cluster.getValue();
				TempCluster.CalculateContribution(this.TotalPacketCount, this.TotalByteCount);
				if (TempCluster.IsBaseType == true)
				{
					this.CopyFromCluster(TempCluster);
				}
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
					Iterator ClusterIterator = BaseClusters.entrySet().iterator();
					BaseCluster VolatileCluster;
					String result;
					while (ClusterIterator.hasNext())
					{
						Map.Entry<String, BaseCluster> Cluster = (Map.Entry<String, BaseCluster>)ClusterIterator.next();
						VolatileCluster = Cluster.getValue();
						result = TrafficCluster.ClusterLabel+VolatileCluster.BaseID + "\t ---- \t" 
								+ IPv4.fromIPv4Address(VolatileCluster.SrcIPMatch) +"\t ---- \t"
								+ IPv4.fromIPv4Address(VolatileCluster.DstIPMatch) + "\t ---- \t" 
								+ VolatileCluster.SrcPort + "\t ---- \t" 
								+ VolatileCluster.DstPort + "\t ---- \t" 
								+ VolatileCluster.Protocol + "\t ---- \t" 
								+ VolatileCluster.TotalPacketCount + "% \t ---- \t"
								+ VolatileCluster.TotalByteCount + "% \n";
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
	
	public class BaseCluster 
	{
		public int BaseID;
		public int SrcIPMatch;
		public int SrcMask=0; //how many octets from left
		
		public int DstIPMatch;
		public int DstMask=0; //how many octets from left e.g. 0=/32 1=/24,2=/16,3=/8 or 4= /0 
		
		public short LowPort;
		public short HighPort;
		public short SrcPort;
		public short DstPort;
		public TrafficType Protocol;
		
		public long TotalPacketCount;
		public double TotalByteCount;
		
		public boolean MatchOnPortRange = false;
		public boolean MatchOnPortExact = false;
		public boolean MatchOnSrcIP = false;
		public boolean MatchOnDstIP = false;
		public boolean MatchOnProtocol = false;
		
		
			
		public BaseCluster(int[] SrcInfo, int[] DstInfo, short[] Ports, TrafficType Protocol, int BaseID)
		{
			this.SrcIPMatch = SrcInfo[0];
			if (this.SrcIPMatch != -1)
			{
				this.MatchOnSrcIP = true;
				this.SrcMask = SrcInfo[1];
				
			}
	
			
			this.DstIPMatch = SrcInfo[0];
			if (this.DstIPMatch != -1)
			{
				this.MatchOnDstIP = true;
				this.DstMask = DstInfo[1];
			}
			
			
			if (Ports[0] == 0)
			{
				this.LowPort = Ports[1];
				this.HighPort = Ports[2];
				this.MatchOnPortRange = true;
			}
			else
			{
				this.SrcPort = Ports[1];
				this.DstPort = Ports[2];
				this.MatchOnPortExact = true;
			}
			
			this.Protocol = Protocol;
			if (this.Protocol != TrafficType.ALL)
			{
				this.MatchOnProtocol = true;
			}
			
			this.BaseID = BaseID;
			this.TotalPacketCount = 0;
			this.TotalByteCount = 0.0;
		}
		
		public void UpdateCount(long PacketCount, double ByteCount)
		{
			this.TotalPacketCount+= PacketCount;
			this.TotalByteCount+= ByteCount;
		}
	}
	
}
