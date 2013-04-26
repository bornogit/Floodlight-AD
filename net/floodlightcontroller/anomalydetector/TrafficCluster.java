package net.floodlightcontroller.anomalydetector;
import java.util.ArrayList;
import java.util.List;

import net.floodlightcontroller.packet.Ethernet;
public class TrafficCluster 
{
	public String ClusterLabel;
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
	public double TotalPacketContribution;
	public double TotalByteContribution;
	private Boolean IsBaseType=true;
	public Boolean NeedDPI;
	private int NumChildren=0;
	private TrafficType Protocol;
	
	private RuleMaker Rule;
	List<Integer> ChildCluster = new ArrayList<Integer>();
	
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
		this.TotalPacketContribution =0;
		this.PacketCount =0;
		
		this.ClusterID = ClusterID;
		this.ClusterLabel = "Cluster-"+this.ClusterID;
		if (HasChild)
		{
			this.IsBaseType = false;
		}
		
	}

	private void AddChildCluster(int ClusterID)
	{
		this.ChildCluster.add(ClusterID);
		this.NumChildren++;
	}
	
	private void RemoveChildCluster()
	{
		if (this.NumChildren>0)
		{
			this.ChildCluster.remove(ClusterID);
			this.NumChildren--;
		}
	}
	
	public void CreateFlowMod(RuleMaker Rule)
	{
		this.Rule = Rule;
		this.Rule.SetParams(this.ClusterLabel,this.SourceIP, this.DestIP, this.SourcePort, this.DestPort, this.Protocol);
		this.Rule.InstallRule();
	}
	
	public void UpdateCount(int PacketCout, int ByteCount)
	{
		this.PacketCount += PacketCount;
		this.TrafficSize += ByteCount;
	}
	
	public void CalculateContribution(int TotalPacketCount, int TotalByteCount)
	{
		this.TotalByteContribution = (this.TrafficSize/TotalByteCount) * 100;
		this.TotalPacketContribution = (this.PacketCount/TotalPacketCount) * 100;
	}
	
}
