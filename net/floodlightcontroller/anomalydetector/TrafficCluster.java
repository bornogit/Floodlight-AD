package net.floodlightcontroller.anomalydetector;
import java.util.ArrayList;
import java.util.List;

import net.floodlightcontroller.packet.Ethernet;
public class TrafficCluster 
{
	private String ClusterLabel;
	private int ClusterID;
	private String SourceIP=null;
	private String DestIP=null;
	private short SourcePort;
	private short DestPort;
	public static enum TrafficType
	{
		TCP, UDP, ICMP
	}
	private int TrafficSize;
	private int PacketCount;
	private int TotalContribution;
	private Boolean IsBaseType=true;
	private Boolean NeedDPI;
	private int NumChildren=0;
	private TrafficType Protocol;
	
	private RuleMaker Rule;
	List<TrafficCluster> ChildCluster = new ArrayList<TrafficCluster>();
	
	public TrafficCluster(Boolean HasChild, String SourceIP, String DestIP,
				short SourcePort, short DestPort, TrafficType Protocol, int ClusterID)
	{
		this.SourceIP = SourceIP;
		this.DestIP = DestIP;
		this.SourcePort = SourcePort;
		this.DestPort = DestPort;
		this.Protocol = Protocol;
		
		this.NumChildren = 0;
		this.NeedDPI = false;
		this.TrafficSize =0;
		this.TotalContribution =0;
		this.PacketCount =0;
		
		this.ClusterID = ClusterID;
		if (HasChild)
		{
			this.IsBaseType = false;
		}
		
	}

	private void AddChildCluster()
	{
		this.NumChildren++;
	}
	
	private void RemoveChildCluster()
	{
		if (this.NumChildren>0)
		{
			this.NumChildren--;
		}
	}
	
	public void CreateFlowMod(RuleMaker Rule)
	{
		this.Rule = Rule;
		this.Rule.SetParams(this.ClusterID,this.SourceIP, this.DestIP, this.SourcePort, this.DestPort, this.Protocol);
		this.Rule.InstallRule();
	}
	
	private void UpdateCount()
	{
		
	}
	
	private void DeleteCluster()
	{
		
	}
}
