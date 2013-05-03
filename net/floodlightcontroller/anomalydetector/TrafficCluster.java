package net.floodlightcontroller.anomalydetector;


import java.util.ArrayList;
import java.util.List;

import org.openflow.protocol.OFMatch;


import net.floodlightcontroller.packet.IPv4;

public class TrafficCluster 
{
	public int SrcIPMatch;
	public int SrcMask=0; //how many octets from left
	
	public int DstIPMatch;
	public int DstMask=0; //how many octets from left e.g. 0=/32 1=/24,2=/16,3=/8 or 4= /0 
	
	public short LowSrcPort;
	public short HighSrcPort;
	public short LowDstPort;
	public short HighDstPort;
	public short SrcPort;
	public short DstPort;
	public TrafficType Protocol;
	
	
	public static String ClusterLabel = "Cluster-";
	public static double CLUSTER_THRESHOLD = 20;
	public long ClusterID;
	
	public long TotalPacketCount=0;
	public double TotalByteCount=0;
	public double TotalPacketContribution=0.0; // %
	

	public double TotalByteContribution=0.0; // %
	
	
	public long AggrPacketCount=0;
	public double AggrByteCount=0;
	
	public boolean MatchOnSrcPortRange = false;
	public boolean MatchOnDstPortRange = false;
	public boolean MatchOnSrcPortExact = false;
	public boolean MatchOnDstPortExact = false;
	
	public boolean MatchOnSrcIP = false;
	public boolean MatchOnDstIP = false;
	public boolean MatchOnProtocol = false;
	public List<Long> ParentClusterIDs;
	
	public boolean IsBaseType = false;
	public boolean AddedToBase = false;
	public boolean DoPrint = false;
	
	public static enum TrafficType
	{
		TCP, UDP, ICMP, ALL
	}

	
	public TrafficCluster(int[] SrcInfo, int[] DstInfo, short[] SrcPorts, short[] DestPorts, TrafficType Protocol, long BaseID)
	{
		this.SrcIPMatch = SrcInfo[0];
		if (this.SrcIPMatch != -1)
		{
			this.MatchOnSrcIP = true;
			this.SrcMask = SrcInfo[1];
			
		}

		this.DstIPMatch = DstInfo[0];
		if (this.DstIPMatch != -1)
		{
			this.MatchOnDstIP = true;
			this.DstMask = DstInfo[1];
		}
		
		if (SrcPorts[0] == -1) // Any Source Port
		{
			this.SrcPort = -1;
		}
		else if (SrcPorts[0] == -2) // Source within a range
		{
			this.LowSrcPort = SrcPorts[1];
			this.HighSrcPort = SrcPorts[2];
			this.MatchOnSrcPortRange = true;
		}
		else
		{
			this.SrcPort = SrcPorts[0]; // Source Port Exactly
			this.MatchOnSrcPortExact = true;
		}
		
		if (DestPorts[0] == -1) // Same as source port notations
		{
			this.DstPort = -1;
		}
		else if (DestPorts[0] == -2)
		{
			this.LowDstPort = DestPorts[1];
			this.HighDstPort = DestPorts[2];
			this.MatchOnDstPortRange = true;
		}
		else
		{
			this.DstPort = SrcPorts[0];
			this.MatchOnDstPortExact = true;
		}
		
		this.Protocol = Protocol;
		if (this.Protocol != TrafficType.ALL)
		{
			this.MatchOnProtocol = true;
		}
		
		this.ClusterID = BaseID;
		this.IsBaseType = true;
	}
	
	public TrafficCluster(OFMatch Match, long ClusterID)
	{
		this.ClusterID = ClusterID;
		this.ParentClusterIDs = new ArrayList<Long>();
		this.IsBaseType = false;
		this.ExtractFields(Match);
	}
	
	private void ExtractFields(OFMatch Match)
	{
		this.SrcIPMatch = Match.getNetworkSource();
		this.DstIPMatch = Match.getNetworkDestination();
		this.SrcPort = Match.getTransportSource();
		this.DstPort = Match.getTransportDestination();
		this.DstMask = Match.getNetworkDestinationMaskLen();
		this.SrcMask = Match.getNetworkSourceMaskLen();
		
		switch (Match.getNetworkProtocol())
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
	
	public void UpdateBaseClusterCount(long PacketCount, double ByteCount)
	{
		this.AggrPacketCount+= PacketCount;
		this.AggrByteCount+= ByteCount;
	}
	
	public void AdjustBaseClusterCount()
	{
		this.TotalPacketCount = this.AggrPacketCount;
		this.TotalByteCount = this.AggrByteCount;
		this.AggrPacketCount = 0;
		this.AggrByteCount = 0;
	}
	
	public void UpdateCount(long PacketCount, double ByteCount)
	{
		this.TotalPacketCount = PacketCount;
		this.TotalByteCount = ByteCount;
	}
	
	
	public void CalculateContribution(long TotalPacketCount, double TotalByteCount)
	{
		this.TotalByteContribution = (this.TotalByteCount* 100.00)/TotalByteCount;
		this.TotalPacketContribution = (this.TotalPacketCount*100.00)/TotalPacketCount;
		if (this.TotalByteContribution >= TrafficCluster.CLUSTER_THRESHOLD)
		{
			this.IsBaseType = true;
			this.DoPrint = true;
		}
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
	
	public static boolean CheckPortMatches(TrafficCluster Base, short InputSrcPort, short InputDstPort)
	{
		boolean SrcPortResult = false;
		boolean DstPortResult = false;
		
		if (Base.MatchOnSrcPortRange == true)
		{
			if ((InputSrcPort >= Base.LowSrcPort) && (InputSrcPort <= Base.HighSrcPort))
			{
				SrcPortResult = true;	
			}
		}
		else if (Base.MatchOnSrcPortExact == true)
		{
			if (InputSrcPort == Base.SrcPort)
			{
				SrcPortResult = true;
			}
		}
		else
		{
			SrcPortResult = true;
		}
		
		if (Base.MatchOnDstPortRange == true)
		{
			if ((InputDstPort >= Base.LowDstPort) && (InputDstPort <= Base.HighDstPort))
			{
				DstPortResult = true;	
			}
		}
		else if (Base.MatchOnDstPortExact == true)
		{
			if (InputDstPort == Base.DstPort)
			{
				DstPortResult = true;
			}
		}
		else
		{
			DstPortResult = true;
		}
			
		
		
		return SrcPortResult && DstPortResult;
	}
	
	public String GetSrcIP()
	{
		String SrcIP;
		if (this.SrcIPMatch== -1)
		{
			SrcIP = "*";
		}
		else
		{
			SrcIP = IPv4.fromIPv4Address(this.SrcIPMatch)+"/"+((4- this.SrcMask)*8); // just converting to the CIDR notation;
		}
		
		return SrcIP;
	}
	
	public String GetDstIP()
	{
		String DstIP;
		if (this.DstIPMatch== -1)
		{
			DstIP = "*";
		}
		else
		{
			DstIP = IPv4.fromIPv4Address(this.DstIPMatch)+"/"+((4- this.DstMask)*8); // just converting to the CIDR notation
		}
		
		return DstIP;
	}
	
	public String GetSrcPort()
	{
		String SrcPort;
		if (this.MatchOnSrcPortRange == true)
		{
			SrcPort = this.LowSrcPort + "-" + this.HighSrcPort;
		}
		else if (this.MatchOnSrcPortExact == true)
		{
			SrcPort = Short.toString(this.SrcPort);
		}
		else
		{
			SrcPort = "*";
		}
		return SrcPort;
	}
	
	public String GetDstPort()
	{
		String DstPort;
		if (this.MatchOnDstPortRange == true)
		{
			DstPort = this.LowDstPort + "-" + this.HighDstPort;
		}
		else if (this.MatchOnDstPortExact == true)
		{
			DstPort = Short.toString(this.DstPort);
		}
		else
		{
			DstPort = "*";
		}
		return DstPort;
	}
	
	public double GetTotalPacketContribution() 
	{
		return (double)Math.round(this.TotalPacketContribution * 100) / 100;
	}

	public double GetTotalByteContribution() 
	{
		return (double)Math.round(this.TotalByteContribution * 100) / 100;
	}

	
	public String GetClusterLabel()
	{
		return TrafficCluster.ClusterLabel + "-" + this.ClusterID;
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

}




