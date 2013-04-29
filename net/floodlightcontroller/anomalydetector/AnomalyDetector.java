package net.floodlightcontroller.anomalydetector;

import java.io.IOException;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import java.util.Map;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.Wildcards;

import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.HexString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;

import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.learningswitch.LearningSwitch;
import net.floodlightcontroller.packet.Ethernet;


import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;



/*	
 * since we are listening to OpenFlow messages we need to 
 * register with the FloodlightProvider (IFloodlightProviderService class
*/
public class AnomalyDetector implements IOFSwitchListener, IOFMessageListener, IFloodlightModule {

	/*
	 * member variables used in AnomalyDetector
	 * */
	protected IStaticFlowEntryPusherService sfp;
	protected IFloodlightProviderService floodlightProvider;
	protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 20; // in seconds
    protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
    protected static short FLOWMOD_PRIORITY  = 1;
	
	//Added the following
	
	
	protected Map<Long, Short> MacToPort;
	protected static Logger logger;
    public static Map<String, DetectionUnit> Detectors;
        
	/*
	 * important to override 
	 * load dependencies and initialize datastructures
	 * */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		Detectors = new HashMap<String, DetectionUnit>();
		MacToPort = new HashMap<Long, Short>();
		logger = LoggerFactory.getLogger(AnomalyDetector.class);
		sfp = context.getServiceImpl(IStaticFlowEntryPusherService.class);
	}
	
	
	@Override
	public void addedSwitch(IOFSwitch sw) 
	{
		DetectionUnit FlowProcessor=new DetectionUnit(sw, sfp);
		Detectors.put(sw.getStringId(), FlowProcessor);
	}
	
	
	@Override
	public void removedSwitch(IOFSwitch sw) 
	{
		Detectors.get(sw.getStringId()).StopMonitoring();
		Detectors.remove(sw.getStringId());
	}
		@Override
	public void switchPortChanged(Long switchId) {
		// TODO Auto-generated method stub
		
	}
	
	
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
        OFMatch match = new OFMatch();
        match.loadFromPacket(((OFPacketIn)msg).getPacketData(), 
        					 ((OFPacketIn)msg).getInPort());
		
		if (match.getDataLayerType() != Ethernet.TYPE_IPv4)
		{
			return Command.CONTINUE;
		}
		switch (msg.getType()) 
		{
			case PACKET_IN:
				return this.ProcessNewFlow(sw, (OFPacketIn) msg, cntx);
			default:
				break;
       }
       return Command.CONTINUE;
   }
	
	 
    private void CreateFlowMod(IOFSwitch sw, short command, int bufferId,OFMatch match, short outPort)
    {
    	long Cookie = (long)(AnomalyDetector.Detectors.get(sw.getStringId()).ClusterID);
    	OFFlowMod flowMod = (OFFlowMod) floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
        AnomalyDetector.Detectors.get(sw.getStringId()).AddCluster(match);
    	flowMod.setMatch(match);
        flowMod.setCookie(Cookie);
        flowMod.setCommand(command);
        
      //  flowMod.setIdleTimeout(LearningSwitch.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
        flowMod.setHardTimeout(AnomalyDetector.FLOWMOD_DEFAULT_HARD_TIMEOUT);
        flowMod.setPriority(AnomalyDetector.FLOWMOD_PRIORITY);
        flowMod.setBufferId(bufferId);
        flowMod.setOutPort((command == OFFlowMod.OFPFC_DELETE) ? outPort : OFPort.OFPP_NONE.getValue());
        flowMod.setFlags((command == OFFlowMod.OFPFC_DELETE) ? 0 : (short) (1 << 0)); // OFPFF_SEND_FLOW_REM

        flowMod.setActions(Arrays.asList((OFAction) new OFActionOutput(outPort, (short) 0xffff)));
        flowMod.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));

        if (logger.isTraceEnabled()) 
        {
        	logger.trace("{} {} flow mod {}", 
                      new Object[]{ sw, (command == OFFlowMod.OFPFC_DELETE) ? "deleting" : "adding", flowMod });
        }
     
        try 
        {
            sw.write(flowMod, null);
        } 
        catch (IOException e)
        {
        	logger.error("Failed to write {} to switch {}", new Object[]{ flowMod, sw }, e);
        }
    }

    private Command ProcessNewFlow(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) 
    {
        // Read in packet data headers by using OFMatch
        OFMatch match = new OFMatch();
        match.loadFromPacket(pi.getPacketData(), pi.getInPort());
        Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
        Long destMac = Ethernet.toLong(match.getDataLayerDestination());
        
         // Now output flow-mod and/or packet
        
        if (!MacToPort.containsKey(sourceMac))
        {
        	MacToPort.put(sourceMac, pi.getInPort());
        }
        Short outPort = MacToPort.get(destMac);
        if (outPort == null) 
        {
        	this.pushPacket(sw, match, pi, OFPort.OFPP_FLOOD.getValue());
        }
        else
        {// Have to fix the wild cards
        	match.setWildcards(Wildcards.FULL.withNwSrcMask(0));
                match.setWildcards(((Integer)sw.getAttribute(IOFSwitch.PROP_FASTWILDCARDS)).intValue()
                  & ~OFMatch.OFPFW_IN_PORT);
      //            & ~OFMatch.OFPFW_DL_VLAN & ~OFMatch.OFPFW_DL_SRC & ~OFMatch.OFPFW_DL_DST
        //          & ~OFMatch.OFPFW_NW_SRC_MASK & ~OFMatch.OFPFW_NW_DST_MASK);
                this.pushPacket(sw, match, pi, outPort);
                this.CreateFlowMod(sw, OFFlowMod.OFPFC_ADD, OFPacketOut.BUFFER_ID_NONE, match, outPort);
                this.CreateFlowMod(sw, OFFlowMod.OFPFC_ADD, -1, match.clone()
                    .setDataLayerSource(match.getDataLayerDestination())
                    .setDataLayerDestination(match.getDataLayerSource())
                    .setNetworkSource(match.getNetworkDestination())
                    .setNetworkDestination(match.getNetworkSource())
                    .setTransportSource(match.getTransportDestination())
                    .setTransportDestination(match.getTransportSource())
                    .setInputPort(outPort),
                    match.getInputPort());
            
        }
        return Command.CONTINUE;
    }
    
    

    private void pushPacket(IOFSwitch sw, OFMatch match, OFPacketIn pi, short outport) 
    {
        if (pi == null)
        {
            return;
        }

        if (pi.getInPort() == outport) 
        {
            if (logger.isDebugEnabled()) 
            {
            	logger.debug("Attempting to do packet-out to the same " + 
                          "interface as packet-in. Dropping packet. " + 
                          " SrcSwitch={}, match = {}, pi={}", 
                          new Object[]{sw, match, pi});
                return;
            }
        }

        if (logger.isTraceEnabled()) 
        {
        	logger.trace("PacketOut srcSwitch={} match={} pi={}", 
                      new Object[] {sw, match, pi});
        }

        OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT);

        // set actions
        List<OFAction> actions = new ArrayList<OFAction>();
        actions.add(new OFActionOutput(outport, (short) 0xffff));

        po.setActions(actions).setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);
        short poLength =  (short) (po.getActionsLength() + OFPacketOut.MINIMUM_LENGTH);

        // If the switch doens't support buffering set the buffer id to be none
        // otherwise it'll be the the buffer id of the PacketIn
        if (sw.getBuffers() == 0) 
        {
            // We set the PI buffer id here so we don't have to check again below
            pi.setBufferId(OFPacketOut.BUFFER_ID_NONE);
            po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
        } 
        else 
        {
            po.setBufferId(pi.getBufferId());
        }

        po.setInPort(pi.getInPort());

        // If the buffer id is none or the switch doesn's support buffering
        // we send the data with the packet out
        if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) 
        {
            byte[] packetData = pi.getPacketData();
            poLength += packetData.length;
            po.setPacketData(packetData);
        }

        po.setLength(poLength);

        try 
        {
         
            sw.write(po, null);
        } 
        catch (IOException e)
        {
            logger.error("Failure writing packet out", e);
        }
    }
    
   
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
	public void startUp(FloodlightModuleContext context) 
	{
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProvider.addOFSwitchListener(this);
	}

	


	

}

