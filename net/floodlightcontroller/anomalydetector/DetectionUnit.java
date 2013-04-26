package net.floodlightcontroller.anomalydetector;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;



import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.anomalydetector.StatCollector.StatResult;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;

public class DetectionUnit implements Runnable
{
	Map<String, TrafficCluster> Clusters = new HashMap<String, TrafficCluster>();
	
	List<StatResult> ClusterStats = new ArrayList<StatResult>();
	public int NumClusters;
	
	private int TotalPacketCount;
	private int TotalByteCount;
	private int BaseClusterCount = 0;
	private static final double TrafficThreshold = 20;
	
	private RuleMaker RuleManager;
	protected static Logger logger;
	protected StatCollector FlowLogger;
	protected volatile Thread th;
	private Boolean IsMonitoring;
	private IOFSwitch sw;
	public DetectionUnit(IOFSwitch sw, IStaticFlowEntryPusherService sfp)
	{
		this.RuleManager = new RuleMaker(sw,sfp);
		logger = LoggerFactory.getLogger(DetectionUnit.class);
		this.NumClusters =0;
		this.TotalByteCount=0;
		this.TotalPacketCount=0;
		this.sw = sw;
		this.IsMonitoring = true;
		this.InitiateBaseClusters();
		this.StartMonitoring();
	}
	
	private void InitiateBaseClusters()
	{
		TrafficCluster NewBaseCluster;
		NewBaseCluster = new TrafficCluster(false, "0.0.0.0", "0.0.0.0", (short)(0), (short)(0),TrafficCluster.TrafficType.TCP, this.NumClusters++);
		this.BaseClusterCount++;
		Clusters.put(NewBaseCluster.ClusterLabel, NewBaseCluster);
		
		NewBaseCluster = new TrafficCluster(false, "0.0.0.0", "0.0.0.0", (short)(0), (short)(0),TrafficCluster.TrafficType.UDP, this.NumClusters++);
		this.BaseClusterCount++;
		Clusters.put(NewBaseCluster.ClusterLabel, NewBaseCluster);
		
		Iterator ClusterIterator = Clusters.entrySet().iterator();
		while (ClusterIterator.hasNext())
		{
			Map.Entry<String, TrafficCluster> Cluster = (Map.Entry<String, TrafficCluster>)ClusterIterator.next();
			Cluster.getValue().CreateFlowMod(this.RuleManager);
			ClusterIterator.remove();
		}
		
	}
	
	private void UpdateClusterStat()
	{
		TrafficCluster VolatileCluster; 
		for (StatResult result: ClusterStats)
		{
			VolatileCluster = Clusters.get(result.FlowName);
			this.TotalPacketCount+= result.PacketCount;
			this.TotalByteCount += result.ByteCount;
			VolatileCluster.UpdateCount(result.PacketCount, result.ByteCount);
			VolatileCluster.CalculateContribution(this.TotalPacketCount, this.TotalByteCount);
		}
		this.ClusterStats.clear();
	}
	
	
	private void DetectAnomaly()
	{
		Iterator ClusterIterator = Clusters.entrySet().iterator();
		TrafficCluster VolatileCluster; 
		while (ClusterIterator.hasNext())
		{
			Map.Entry<String, TrafficCluster> Cluster = (Map.Entry<String, TrafficCluster>)ClusterIterator.next();
			VolatileCluster = Cluster.getValue();
			if (VolatileCluster.TotalByteContribution >= DetectionUnit.TrafficThreshold)
			{
				VolatileCluster.NeedDPI = true;
				// DPI
			}
		}
	}
	
	public void StartMonitoring()
	{
		this.FlowLogger = new StatCollector(sw.getStringId(), "flow");
		th = new Thread(this);
		th.start();
	}
	
	public void StopMonitoring()
	{
		this.IsMonitoring = false;
	}

	public void run()
	{
		
		while(this.IsMonitoring)
		{	
			try
			{
				this.ClusterStats=this.FlowLogger.GetCounts();
				this.UpdateClusterStat();
				Thread.sleep(10000);
			}
			catch(Exception e)
			{
				e.printStackTrace();
			}
		} 
		
	}
}
