package net.floodlightcontroller.anomalydetector;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
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
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;


/*	
 * since we are listening to OpenFlow messages we need to 
 * register with the FloodlightProvider (IFloodlightProviderService class
*/
public class AnomalyDetector implements IOFMessageListener, IFloodlightModule, Runnable {

	/*
	 * member variables used in AnomalyDetector
	 * */
	protected IStaticFlowEntryPusherService sfp;
	protected IRestApiService restApi;
	protected IFloodlightProviderService floodlightProvider;
	protected Map<Long, Short> macToPort;
	protected static Logger logger;
	
	//Added the following
	protected int flowNum;
	protected StatCollector FlowLogger;
	protected boolean firstTime;
	protected Thread th;
	protected Map<String, Map<String, OFFlowMod>> flowLog;
	protected OFMatch flowMatch;
	protected OFFlowMod flowMap; 
	protected PrintWriter logWriter;
	
	// 0 - NOTHING, 1 - HUB, 2 - LEARNING_SWITCH_WO_RULES, 3 - LEARNING_SWITCH_WITH_RULES
	protected static int CTRL_LEVEL = 3;
    protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 20; // in seconds
    protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
	
    
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
		sfp = context.getServiceImpl(IStaticFlowEntryPusherService.class);
		flowNum = 1;
		FlowLogger = new StatCollector("flow");
		firstTime = true;
		th = new Thread(this);
		flowMatch = new OFMatch();
		flowMap = new OFFlowMod();
	}


	
    
	/*
	 * push a packet-out to the switch
	 * */
	private void pushPacket(IOFSwitch sw, OFMatch match, OFPacketIn pi, short outport) 
	{
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
	private Command ctrlLogicWithRules(IOFSwitch sw, OFPacketIn pi) 
	{
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
	private Command ctrlLogicWithoutRules(IOFSwitch sw, OFPacketIn pi) 
	{
	    // Read in packet data headers by using OFMatch
        OFMatch match = new OFMatch();
        match.loadFromPacket(pi.getPacketData(), pi.getInPort());
		
		// take the source and destination mac from the packet
		Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
        Long destMac   = Ethernet.toLong(match.getDataLayerDestination());
        
        Short inputPort = pi.getInPort();
        
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
	
	/*
	 * adding flow rules using Static Flow Pusher API
	 */
	private Command addStaticRules(IOFSwitch sw, OFPacketIn pi)
	{
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
 			
 			String flowName = "flow-";
 			flowName = flowName + Integer.toString(flowNum);
 			flowNum++; 
 			logger.debug("install rule for flowName {}", flowName);
 			
 			try {
 				//sw.write(rule, null);
 				sfp.addFlow(flowName, rule, sw.getStringId());
 			} catch (Exception e) {
 				e.printStackTrace();
 			}	
        
        // push the packet to the switch	
        	this.pushPacket(sw, match, pi, outPort);        	
        }       
        
        return Command.CONTINUE;
		
	}
	
	
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
		if (firstTime)
		{
			th.start();
			//FlowLogger.Connect();
			firstTime = false;
		}
        OFMatch match = new OFMatch();
        match.loadFromPacket(((OFPacketIn)msg).getPacketData(), 
        					 ((OFPacketIn)msg).getInPort());
		
		if (match.getDataLayerType() != Ethernet.TYPE_IPv4)
			return Command.CONTINUE;
		
		switch (msg.getType()) {
		
			case PACKET_IN:
				//logger.debug("Receive a packet !");
				
				return this.addStaticRules(sw, (OFPacketIn) msg);
				/*if (AnomalyDetector.CTRL_LEVEL == 1)
					return this.ctrlLogicHub(sw, (OFPacketIn) msg);
				else if (AnomalyDetector.CTRL_LEVEL == 2)
					return this.ctrlLogicWithoutRules(sw, (OFPacketIn) msg);					
				else if (AnomalyDetector.CTRL_LEVEL == 3)
					return this.ctrlLogicWithRules(sw, (OFPacketIn) msg);
				 */
				
			default:
				break;
       }
       logger.error("received an unexpected message {} from switch {}", msg, sw);
       return Command.CONTINUE;
   }

	public void run()
	{
		while(true)
		{	
			try
			{
				logWriter = new PrintWriter("Log_User_Readable.txt");
				logger.debug("<<<<<<<<<<<<IN RUN!!!!>>>>>>>>");
				//FlowLogger.Connect();
				flowLog = sfp.getFlows();
				Iterator it = flowLog.entrySet().iterator();
				while(it.hasNext())
				{
					Map.Entry sw = (Map.Entry) it.next();
					Map temp;
					temp = (Map) sw.getValue();
					
					Iterator it2 = temp.entrySet().iterator();
					while(it2.hasNext())
					{
						Map.Entry name = (Map.Entry) it2.next();
						flowMap = (OFFlowMod) name.getValue();
						flowMatch = flowMap.getMatch();
						
						/*System.out.println(name);
						System.out.println(IPv4.fromIPv4Address(flowMatch.getNetworkSource()));
						System.out.println(flowMatch.getNetworkSourceMaskLen());
						System.out.println(IPv4.fromIPv4Address(flowMatch.getNetworkDestination()));
						System.out.println(flowMatch.getNetworkDestinationMaskLen());
						System.out.println(flowMatch.getNetworkProtocol());
						System.out.println((short)flowMatch.getTransportSource());
						System.out.println((short)flowMatch.getTransportDestination());*/
						
						//logWriter.append(name);
						logWriter.append(IPv4.fromIPv4Address(flowMatch.getNetworkSource()));
						logWriter.append("/");
						logWriter.append(String.valueOf(flowMatch.getNetworkSourceMaskLen()));
						logWriter.append(" ");
						logWriter.append(IPv4.fromIPv4Address(flowMatch.getNetworkDestination()));
						logWriter.append("/");
						logWriter.append(String.valueOf(flowMatch.getNetworkDestinationMaskLen()));
						logWriter.append(" ");
						logWriter.append(String.valueOf(flowMatch.getNetworkProtocol()));
						logWriter.append(" ");
						logWriter.append(String.valueOf(flowMatch.getTransportSource()));
						logWriter.append(" ");
						logWriter.append(String.valueOf(flowMatch.getTransportDestination()));
						logWriter.println();
					}
				}
				
				logWriter.close();
				Thread.sleep(10000);
			}
			catch(Exception e)
			{
				e.printStackTrace();
			}
		} // while 1 loop
	}
			
	/*
	 * 
	 * Put the functions that we don't need to change after this block	
	 */

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
		fsrv.add(IStaticFlowEntryPusherService.class);
		return fsrv;
	}

	/*
	 * important to override 
	 * implement the basic listener - listen for PACKET_IN messages
	 * */
	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		
	}		
}

