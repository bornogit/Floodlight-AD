package net.floodlightcontroller.anomalydetector;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionTransportLayerDestination;
import org.openflow.protocol.action.OFActionTransportLayerSource;
import org.openflow.util.U16;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;


/*	
 * since we are listening to OpenFlow messages we need to 
 * register with the FloodlightProvider (IFloodlightProviderService class
*/
public class AnomalyDetector implements IOFMessageListener, IFloodlightModule {

	/*
	 * member variables used in LearningSwitch
	 * */
	protected IFloodlightProviderService floodlightProvider;
	protected Map<Long, Short> macToPort;
	protected static Logger logger;
	
	// 0 - NOTHING, 1 - HUB, 2 - LEARNING_SWITCH_WO_RULES, 3 - LEARNING_SWITCH_WITH_RULES
	// 4 - Firewall
	// 5 - NAT
	protected static int CTRL_LEVEL = 4;
    protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 30; // in seconds
    protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
	
	/*
	 * important to override 
	 * put an ID for our OFMessage listener
	 * */
	@Override
	public String getName() {
		return AnomalyDetector.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	/*
	 * important to override 
	 * need to wire up to the module loading system by telling the 
	 * module loader we depend on it 
	 * */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService >> fsrv = 
			new ArrayList<Class<? extends IFloodlightService>>();
		fsrv.add(IFloodlightProviderService.class);
		return fsrv;
	}

	/*
	 * important to override 
	 * load dependencies and initialize datastructures
	 * */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		macToPort 		   = new HashMap<Long, Short>();
		logger    		   = LoggerFactory.getLogger(AnomalyDetector.class);
	}

	/*
	 * important to override 
	 * implement the basic listener - listen for PACKET_IN messages
	 * */
	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}
	
	/*
	 * push a packet-out to the switch
	 * */
	private void pushPacket(IOFSwitch sw, OFMatch match, OFPacketIn pi, short outport) {
		
		// create an OFPacketOut for the pushed packet
        OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
                		.getMessage(OFType.PACKET_OUT);        
        
        // update the inputPort and bufferID
        po.setInPort(pi.getInPort());
        po.setBufferId(pi.getBufferId());
                
        // define the actions to apply for this packet
        OFActionOutput action = new OFActionOutput();
		action.setPort(outport);		
		po.setActions(Collections.singletonList((OFAction)action));
		po.setActionsLength((short)OFActionOutput.MINIMUM_LENGTH);
	        
        // set data if it is included in the packet in but buffer id is NONE
        if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
            byte[] packetData = pi.getPacketData();
            po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
                    + po.getActionsLength() + packetData.length));
            po.setPacketData(packetData);
        } else {
            po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
                    + po.getActionsLength()));
        }        
        
        // push the packet to the switch
        try {
            sw.write(po, null);
        } catch (IOException e) {
            logger.error("failed to write packetOut: ", e);
        }
	}
	
		
	/*
	 * control logic which install static rules 
	 * */
	private Command ctrlLogicWithRules(IOFSwitch sw, OFPacketIn pi) {
		
        // Read in packet data headers by using an OFMatch structure
        OFMatch match = new OFMatch();
        match.loadFromPacket(pi.getPacketData(), pi.getInPort());		
        
		// take the source and destination mac from the packet
		Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
        Long destMac   = Ethernet.toLong(match.getDataLayerDestination());
        
        Short inputPort = pi.getInPort();
        
        // if the (sourceMac, port) does not exist in MAC table
        // 		add a new entry
        if (!macToPort.containsKey(sourceMac)) 
        	macToPort.put(sourceMac, inputPort);
        
       
        // if the destMac is in the MAC table take the outPort and send it there
        Short outPort = macToPort.get(destMac);
        
        // if an entry does exist for destMac
        //		flood the packet
        if (outPort == null) 
        	this.pushPacket(sw, match, pi, (short)OFPort.OFPP_FLOOD.getValue());                	
        else {
    	        	
    	// otherwise install a rule s.t. all the traffic with the destination
        // destMac should be forwarded on outPort
        		            
        	// create the rule and specify it's an ADD rule
        	OFFlowMod rule = new OFFlowMod();
 			rule.setType(OFType.FLOW_MOD); 			
 			rule.setCommand(OFFlowMod.OFPFC_ADD);
 			
 			// specify that all fields except destMac to be wildcarded
 			match.setWildcards(~OFMatch.OFPFW_DL_DST);
 			//match.setDataLayerDestination(match.getDataLayerDestination());
 			rule.setMatch(match);
 			
 			// specify timers for the life of the rule
 			rule.setIdleTimeout(AnomalyDetector.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
 			rule.setHardTimeout(AnomalyDetector.FLOWMOD_DEFAULT_HARD_TIMEOUT);
 	        
 	        // set the buffer id to NONE - implementation artifact
 			rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
 	       
 	        // set of actions to apply to this rule
 			ArrayList<OFAction> actions = new ArrayList<OFAction>();
 			OFAction outputTo = new OFActionOutput(outPort);
 			actions.add(outputTo);
 			rule.setActions(actions);
 			 			
 			// specify the length of the flow structure created
 			rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH)); 			
 				
 			logger.debug("install rule for destination {}", destMac);
 			
 			try {
 				sw.write(rule, null);
 			} catch (Exception e) {
 				e.printStackTrace();
 			}	
        
        // push the packet to the switch	
        	this.pushPacket(sw, match, pi, outPort);        	
        }       
        
        return Command.CONTINUE;
	}

	
	/*
	 * control logic which handles each packet in
	 */
	private Command ctrlLogicWithoutRules(IOFSwitch sw, OFPacketIn pi) {
		
        // Read in packet data headers by using OFMatch
        OFMatch match = new OFMatch();
        match.loadFromPacket(pi.getPacketData(), pi.getInPort());
		
		// take the source and destination mac from the packet
		Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
        Long destMac   = Ethernet.toLong(match.getDataLayerDestination());
        
        Short inputPort = pi.getInPort();
        match.getNetworkDestination();
        // if the (sourceMac, port) does not exist in MAC table
        //		add a new entry
        if (!macToPort.containsKey(sourceMac))
        	macToPort.put(sourceMac, inputPort);
        
        // if the destMac is in the MAC table take the outPort and send it there
        Short outPort = macToPort.get(destMac);
        this.pushPacket(sw, match, pi, 
       		(outPort == null) ? (short)OFPort.OFPP_FLOOD.getValue() : outPort);
        
        return Command.CONTINUE;
	}
	
	/*
	 * hub implementation
	 * */
	private Command ctrlLogicHub(IOFSwitch sw, OFPacketIn pi) {

        OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
                		.getMessage(OFType.PACKET_OUT);
        po.setBufferId(pi.getBufferId())
          .setInPort(pi.getInPort());

        // set actions
        OFActionOutput action = new OFActionOutput()
            .setPort((short) OFPort.OFPP_FLOOD.getValue());
        po.setActions(Collections.singletonList((OFAction)action));
        po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);

        // set data if is is included in the packetin
        if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
            byte[] packetData = pi.getPacketData();
            po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
                    + po.getActionsLength() + packetData.length));
            po.setPacketData(packetData);
        } else {
            po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
                    + po.getActionsLength()));
        }
        try {
            sw.write(po, null);
        } catch (IOException e) {
            logger.error("Failure writing PacketOut", e);
        }
		
		return Command.CONTINUE;
	}
	
/* Firewall */
	
	private Command firewall(IOFSwitch sw, OFPacketIn pi)
	{
		//input port
		short inPort = pi.getInPort();
						
		// Reading packet data headers using OFMatch
		OFMatch match  = new OFMatch();
		match.loadFromPacket(pi.getPacketData(), inPort);
		
		//get the network protocol
		byte inNetworkProtocol = match.getNetworkProtocol();
		int tcpDestPort = match.getTransportDestination();
		
		logger.debug("Running Firewall");
		if ((inNetworkProtocol == 0x11) || (tcpDestPort == 23))
		{
			logger.debug("Firewall Rule Matched");
			//set the rules
			OFFlowMod rule = new OFFlowMod();
			rule.setType(OFType.FLOW_MOD); //type is flow modification rule
			rule.setCommand(OFFlowMod.OFPFC_ADD); // Command to add rule
			match.setWildcards(~OFMatch.OFPFW_TP_DST);
			rule.setMatch(match);
			rule.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT);
			rule.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT);
			rule.setBufferId(OFPacketOut.BUFFER_ID_NONE); // Setting buffer id to none;
			rule.setMatch(match);
			ArrayList<OFAction> actions = new ArrayList<OFAction>();
 			OFAction action = null;
 			actions.add(action);
 			rule.setActions(null);
			rule.setLength((short)(OFFlowMod.MINIMUM_LENGTH));
			try
			{
				sw.write(rule, null);
			}
			catch (Exception e)
			{
				logger.error(e.getMessage());
				e.printStackTrace();
			}
			return Command.CONTINUE;
			 // push the packet to the switch, do we need to in this case?	
        	//this.pushPacket(sw, match, pi, outPort);
			//ctrlLogicWithRules(sw, pi);
		}
		else
		{
			return this.ctrlLogicWithRules(sw, pi);
		}
		
		
	}

	
/* NAT */
	
	private Command nat(IOFSwitch sw, OFPacketIn pi)
	{
		//input port
		short inPort = pi.getInPort();
						
		// Reading packet data headers using OFMatch
		OFMatch match  = new OFMatch();
		match.loadFromPacket(pi.getPacketData(), inPort);
		
		//get the network protocol
		byte inNetworkProtocol = match.getNetworkProtocol();
		short tcpDestPort = (short) match.getNetworkDestination();
		short tcpSrcPort = (short) match.getNetworkSource();
		short changedTransportPort = 443;
		
		if (inNetworkProtocol == 0x06)
		{
			//set the rules
			OFFlowMod rule = new OFFlowMod();
			rule.setType(OFType.FLOW_MOD); //type is flow modification rule
			rule.setCommand(OFFlowMod.OFPFC_ADD); // Command to add rule
			rule.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT);
			rule.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT);
			rule.setBufferId(OFPacketOut.BUFFER_ID_NONE); // Setting buffer id to none;
			rule.setLength((short)(OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH) );
			//come back here to decide on the output length
			
			// set of actions to apply to this rule
 			ArrayList<OFAction> actions = new ArrayList<OFAction>();
 			OFAction changePortAction = null;
 			if (tcpDestPort == 443)
			{
				match.setWildcards(~OFMatch.OFPFW_TP_DST);
				changePortAction = new OFActionTransportLayerDestination((short)80);
				logger.debug("Destination Port 443 Detected");
			}
			else if (tcpSrcPort == 80)
			{
				match.setWildcards(~OFMatch.OFPFW_TP_SRC);
				changePortAction = new OFActionTransportLayerSource(changedTransportPort);
				logger.debug("Source Port 80 Detected");
			}
			actions.add(changePortAction);
			rule.setActions(actions);
			rule.setMatch(match);
			try
			{
				sw.write(rule, null);
			}
			catch (Exception e)
			{
				logger.error(e.getMessage());
				e.printStackTrace();
			}
			 // push the packet to the switch	
        	//this.pushPacket(sw, match, pi, outPort);
			ctrlLogicWithRules(sw, pi);
		}
		return Command.CONTINUE;
	}

	
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
				
        OFMatch match = new OFMatch();
        match.loadFromPacket(((OFPacketIn)msg).getPacketData(), 
        					 ((OFPacketIn)msg).getInPort());
		
		if (match.getDataLayerType() != Ethernet.TYPE_IPv4)
			return Command.CONTINUE;
		if (msg.getType() == org.openflow.protocol.OFType.PACKET_IN)
		{
			logger.debug("Receive a packet !");
			
			switch (AnomalyDetector.CTRL_LEVEL)
			{
				case 1:
					return this.ctrlLogicHub(sw, (OFPacketIn) msg);
				case 2:
					return this.ctrlLogicWithoutRules(sw, (OFPacketIn) msg);
				case 3:
					return this.ctrlLogicWithRules(sw, (OFPacketIn) msg);
				case 4:
					return this.firewall(sw, (OFPacketIn)msg);
				case 5:
					return this.nat(sw, (OFPacketIn) msg);
				default:
					break;
			}
		}
		logger.error("received an unexpected message {} from switch {}", msg, sw);
	    return Command.CONTINUE;
   }

}
