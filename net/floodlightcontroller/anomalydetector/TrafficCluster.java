package net.floodlightcontroller.anomalydetector;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

import org.openflow.protocol.OFMatch;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
public class TrafficCluster 
{
	public static String ClusterLabel = "Cluster-";
	public long ClusterID;
	public String SourceIP;
	public String DestIP;
	public String SourcePort;
	public String DestPort;
	public TrafficType Protocol;
	
	public static enum TrafficType
	{
		TCP, UDP, ICMP, ALL
	}
	private double ByteCount;
	private long PacketCount;
	public double TotalPacketContribution;
	public double TotalByteContribution;
	private Boolean IsBaseType=true;
	public Boolean NeedDPI;
	private int NumChildren=0;
	
	OFMatch ClusterSignature;
	private RuleMaker Rule;
	List<Integer> ChildCluster = new ArrayList<Integer>();
	
	public TrafficCluster(OFMatch Match, Boolean HasChild, int ClusterID)
	{
		
		this.ClusterSignature = Match;
		this.NumChildren = 0;
		this.NeedDPI = false;
		this.ByteCount =0;
		this.TotalPacketContribution =0.0;
		this.TotalByteContribution =0.0;
		this.PacketCount =0;
		this.ClusterID = (long)ClusterID;
		
		if (HasChild)
		{
			this.IsBaseType = false;
		}
		
		this.ExtractFields();
	}
	
	private void ExtractFields()
	{
		this.SourceIP = IPv4.fromIPv4Address(this.ClusterSignature.getNetworkSource());
		this.DestIP = IPv4.fromIPv4Address(this.ClusterSignature.getNetworkDestination());
		this.SourcePort = Short.toString(this.ClusterSignature.getTransportSource());
		this.DestPort = Short.toString(this.ClusterSignature.getTransportDestination());
		TrafficCluster.TrafficType Protocol;
		switch (this.ClusterSignature.getNetworkProtocol())
		{
			case IPv4.PROTOCOL_TCP:
				this.Protocol = TrafficCluster.TrafficType.TCP;
				break;
			case IPv4.PROTOCOL_UDP:
				this.Protocol = TrafficCluster.TrafficType.UDP;
				break;
			case IPv4.PROTOCOL_ICMP:
				this.Protocol = TrafficCluster.TrafficType.ICMP;
				break;
			default:
				this.Protocol = TrafficCluster.TrafficType.ALL;
				break;
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
		//Will create new deeper cluster from the existing match
	//	this.Rule.SetParams(this.ClusterLabel,this.SourceIP, this.DestIP, this.SourcePort, this.DestPort, this.Protocol);
		this.Rule.InstallRule();
	}
	
	public void UpdateCount( long PacketCount, double ByteCount)
	{
		this.PacketCount = PacketCount;
		this.ByteCount = ByteCount;
	}
	
	public void CalculateContribution(long TotalPacketCount, double TotalByteCount)
	{
		this.TotalByteContribution = (this.ByteCount* 100.00)/TotalByteCount;
		this.TotalPacketContribution = (this.PacketCount*100.00)/TotalPacketCount;
		if (this.TotalByteContribution >= DetectionUnit.CLUSTER_THRESHOLD)
		{
			this.NeedDPI = true;
		}
	}
	
}
