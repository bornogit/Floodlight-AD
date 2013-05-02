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
	public static double CLUSTER_THRESHOLD = 20;
	public long ClusterID;
	public int SourceIP;
	public int DestIP;
	public Short SourcePort;
	public Short DestPort;
	public TrafficType Protocol;
	public int DestMask;
	public int SrcMask;
	public List<Integer> ParentClusterIDs;
	
	public static enum TrafficType
	{
		TCP, UDP, ICMP, ALL
	}
	private double ByteCount;
	private long PacketCount;
	public double TotalPacketContribution;
	public double TotalByteContribution;
	
	OFMatch ClusterSignature;
	
	public boolean IsBaseType = false;
	
	List<Integer> ChildCluster = new ArrayList<Integer>();
	
	public TrafficCluster(OFMatch Match, long ClusterID)
	{
		
		this.ClusterSignature = Match;
		this.ByteCount =0;
		this.TotalPacketContribution =0.0;
		this.TotalByteContribution =0.0;
		this.PacketCount =0;
		this.ClusterID = ClusterID;
		
		this.ParentClusterIDs = new ArrayList();
		this.ExtractFields();
	}
	
	private void ExtractFields()
	{
		this.SourceIP = this.ClusterSignature.getNetworkSource();
		this.DestIP = this.ClusterSignature.getNetworkDestination();
		this.SourcePort =this.ClusterSignature.getTransportSource();
		this.DestPort = this.ClusterSignature.getTransportDestination();
		this.DestMask = this.ClusterSignature.getNetworkDestinationMaskLen();
		this.SrcMask = this.ClusterSignature.getNetworkSourceMaskLen();
		
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

	
	public void UpdateCount( long PacketCount, double ByteCount)
	{
		this.PacketCount = PacketCount;
		this.ByteCount = ByteCount;
	}
	
	public void CalculateContribution(long TotalPacketCount, double TotalByteCount)
	{
		this.TotalByteContribution = (this.ByteCount* 100.00)/TotalByteCount;
		this.TotalPacketContribution = (this.PacketCount*100.00)/TotalPacketCount;
		if (this.TotalByteContribution >= TrafficCluster.CLUSTER_THRESHOLD)
		{
			this.IsBaseType = true;
		}
	}
	
}




