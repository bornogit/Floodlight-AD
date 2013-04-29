package net.floodlightcontroller.anomalydetector;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;


import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFStatisticsReply;
import org.openflow.protocol.OFStatisticsRequest;
import org.openflow.protocol.OFType;
import org.openflow.protocol.Wildcards;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionDataLayerDestination;
import org.openflow.protocol.action.OFActionDataLayerSource;
import org.openflow.protocol.action.OFActionEnqueue;
import org.openflow.protocol.action.OFActionNetworkLayerDestination;
import org.openflow.protocol.action.OFActionNetworkLayerSource;
import org.openflow.protocol.action.OFActionNetworkTypeOfService;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionStripVirtualLan;
import org.openflow.protocol.action.OFActionTransportLayerDestination;
import org.openflow.protocol.action.OFActionTransportLayerSource;
import org.openflow.protocol.action.OFActionType;
import org.openflow.protocol.action.OFActionVirtualLanIdentifier;
import org.openflow.protocol.action.OFActionVirtualLanPriorityCodePoint;
import org.openflow.protocol.statistics.OFFlowStatisticsRequest;
import org.openflow.protocol.statistics.OFStatistics;
import org.openflow.protocol.statistics.OFStatisticsType;
import org.openflow.util.HexString;
import org.openflow.util.U16;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class RuleMaker 
{
	private Map<String, String> Actions = null;
	
	private short Priority;
	private boolean Active;
	
	private short EtherType;
	private byte Protocol;
	private String SrcIP = null;
	private String DstIP = null;
	private short SrcPort;
	private short DstPort;
	
	private String FlowName;
	
	private IOFSwitch sw;
	private Logger logger;
	protected IStaticFlowEntryPusherService sfp;
	protected OFMatch FlowMatch;
	protected OFFlowMod rule;
	
	protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 20; // in seconds
    protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
	
    protected Map<String, OFFlowMod> Stats = new HashMap<String, OFFlowMod>();
    
	public RuleMaker(IOFSwitch sw, IStaticFlowEntryPusherService sfp)
	{
		this.sw = sw;
		this.sfp = sfp;
	}
	
	
	public void PushFlowMod()
	{
		//this.sfp.addFlow(this.FlowName, this.rule, this.sw.getStringId());
	}
	
	
	
	private void RemoveFlowMod()
	{
		//this.sfp.deleteFlow(this.FlowName);
	}
	
	public void SetParams(String ClusterLabel, String SrcIP, String DstIP, short SrcPort, short DstPort, TrafficCluster.TrafficType Protocol)
	{
		this.SrcIP = SrcIP;
		this.DstIP = DstIP;
		this.SrcPort = SrcPort;
		this.DstPort = DstPort;
		this.Priority=999;
		switch (Protocol)
		{
			case TCP:
				this.Protocol = IPv4.PROTOCOL_TCP;
				break;
			case UDP:
				this.Protocol = IPv4.PROTOCOL_UDP;
			case ICMP:
				this.Protocol = IPv4.PROTOCOL_ICMP;
				break;
		}
		this.FlowName = ClusterLabel;
	
	}
	
	private void CreateMod()
	{
		this.FlowMatch = new OFMatch();
		this.FlowMatch.setNetworkSource(IPv4.toIPv4Address(this.SrcIP));
		this.FlowMatch.setNetworkDestination(IPv4.toIPv4Address(this.DstIP));
	    this.FlowMatch.setDataLayerType(Ethernet.TYPE_IPv4); 
	   this.FlowMatch.setNetworkProtocol(this.Protocol);
	    this.FlowMatch.setTransportSource(this.SrcPort);
	   this.FlowMatch.setTransportDestination(this.DstPort);
	//	this.FlowMatch.setWildcards(Wildcards.FULL.withNwSrcMask(0));
		
	  //this.FlowMatch.setWildcards(((Integer)sw.getAttribute(IOFSwitch.PROP_FASTWILDCARDS)).intValue()
           //    & ~OFMatch.OFPFW_IN_PORT
          //     & ~OFMatch.OFPFW_DL_VLAN & ~OFMatch.OFPFW_DL_SRC & ~OFMatch.OFPFW_DL_DST
          //     & ~OFMatch.OFPFW_NW_SRC_MASK & ~OFMatch.OFPFW_NW_DST_MASK);
		
        //match.loadFromPacket(pi.getPacketData(), pi.getInPort());
       
      	rule = new OFFlowMod();
      	rule.setCookie((long)1);
		rule.setType(OFType.FLOW_MOD);
		rule.setCommand(OFFlowMod.OFPFC_ADD);
 		rule.setMatch(FlowMatch);
 		rule.setHardTimeout(RuleMaker.FLOWMOD_DEFAULT_HARD_TIMEOUT);
 		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
  		ArrayList<OFAction> actions = new ArrayList<OFAction>();
 		OFAction outputTo = new OFActionOutput(OFPort.OFPP_NORMAL.getValue());
 		rule.setActions(actions);
 		rule.setPriority(this.Priority);	 			
		rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH)); 			
	}
	

	public void InstallRule()
	{
		this.CreateMod();
		this.PushFlowMod();
	}
	

}
