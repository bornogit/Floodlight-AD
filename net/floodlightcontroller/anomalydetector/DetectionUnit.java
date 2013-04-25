package net.floodlightcontroller.anomalydetector;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.Future;

import org.openflow.protocol.OFStatisticsRequest;
import org.openflow.protocol.statistics.OFFlowStatisticsRequest;
import org.openflow.protocol.statistics.OFStatistics;
import org.openflow.protocol.statistics.OFStatisticsType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;

public class DetectionUnit implements Runnable
{
	List<TrafficCluster> BaseClusters = new ArrayList<TrafficCluster>();
	public int NumClusters;
	private int TotalPacketCount;
	private int TotalByteCount;
	private int BaseClusterCount = 0;
	
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
		this.sw = sw;
		this.IsMonitoring = true;
		this.InitiateBaseClusters();
		this.StartMonitoring();
	}
	
	private void InitiateBaseClusters()
	{
		TrafficCluster NewBaseCluster;
		NewBaseCluster = new TrafficCluster(false, "0.0.0.0", "0.0.0.0", (short)(0), (short)(0),TrafficCluster.TrafficType.TCP, this.NumClusters++);
		BaseClusters.add(NewBaseCluster);
		
		NewBaseCluster = new TrafficCluster(false, "0.0.0.0", "0.0.0.0", (short)(0), (short)(0),TrafficCluster.TrafficType.UDP, this.NumClusters++);
		BaseClusters.add(NewBaseCluster);
		
		for(TrafficCluster Cluster: BaseClusters)
		{
			Cluster.CreateFlowMod(this.RuleManager);
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
				this.FlowLogger.Connect();
				Thread.sleep(10000);
							
			}
			catch(Exception e)
			{
				e.printStackTrace();
			}
		} 
		
	}
}
