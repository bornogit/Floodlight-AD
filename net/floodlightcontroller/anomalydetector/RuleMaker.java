package net.floodlightcontroller.anomalydetector;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
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
import org.openflow.protocol.action.OFActionVirtualLanIdentifier;
import org.openflow.protocol.action.OFActionVirtualLanPriorityCodePoint;
import org.openflow.util.HexString;
import org.openflow.util.U16;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.anomalydetector.TrafficCluster.TrafficType;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.counter.ICounterStoreService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.util.MACAddress;
import net.floodlightcontroller.util.OFMessageDamper;

public class RuleMaker 
{
	private String SwitchDpid = null;
	
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
	
	public RuleMaker(IOFSwitch sw, IStaticFlowEntryPusherService sfp)
	{
		this.sw = sw;
		this.sfp = sfp;
	}
	
	
	private void PushFlowMod()
	{
		this.sfp.addFlow(this.FlowName, this.rule, this.sw.getStringId());
	}
	
	public void SetParams(int ClusterID, String SrcIP, String DstIP, short SrcPort, short DstPort, TrafficCluster.TrafficType Protocol)
	{
		this.SrcIP = SrcIP;
		this.DstIP = DstIP;
		this.SrcPort = SrcPort;
		this.DstPort = DstPort;
		this.Priority=0;
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
		this.FlowName = "flow-"+ Integer.toString(ClusterID);
	
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
	    
		
        //match.loadFromPacket(pi.getPacketData(), pi.getInPort());
       
        
              
       	// create the rule and specify it's an ADD rule
       	rule = new OFFlowMod();
		rule.setType(OFType.FLOW_MOD); 			
		rule.setCommand(OFFlowMod.OFPFC_ADD);
 		rule.setMatch(FlowMatch);
		rule.setIdleTimeout(RuleMaker.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
 		rule.setHardTimeout(RuleMaker.FLOWMOD_DEFAULT_HARD_TIMEOUT);
 		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
 	     
 	    // set of actions to apply to this rule
 		ArrayList<OFAction> actions = new ArrayList<OFAction>();
// 		OFAction outputTo = new OFActionOutput((short)2);
 		rule.setActions(actions);
 		rule.setPriority(this.Priority);	 			
		// specify the length of the flow structure created
		rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH)); 			
		
		
    
	}
	
	public void InstallRule()
	{
		this.CreateMod();
		this.PushFlowMod();
	}
	

}
