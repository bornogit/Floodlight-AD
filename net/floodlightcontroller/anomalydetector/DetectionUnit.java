package net.floodlightcontroller.anomalydetector;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;

public class DetectionUnit 
{
	List<TrafficCluster> BaseClusters = new ArrayList<TrafficCluster>();
	public int NumClusters;
	private int TotalPacketCount;
	private int TotalByteCount;
	private int BaseClusterCount = 0;
	
	private RuleMaker RuleManager;
	protected static Logger logger;
	
	public DetectionUnit(IOFSwitch sw, IStaticFlowEntryPusherService sfp)
	{
		this.RuleManager = new RuleMaker(sw,sfp);
		logger = LoggerFactory.getLogger(DetectionUnit.class);
		this.NumClusters =0;
		this.InitiateBaseClusters();
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

}
