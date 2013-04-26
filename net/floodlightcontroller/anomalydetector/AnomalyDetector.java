package net.floodlightcontroller.anomalydetector;

import java.io.IOException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import java.util.Map;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;

import org.openflow.protocol.OFType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;

import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
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
	
	
	
	//Added the following
	
	
	protected Map<String, Map<String, OFFlowMod>> flowLog;
	protected static Logger logger;
    protected Map<String, DetectionUnit> Detectors;
        
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
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
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
			break;
			default:
				break;
       }
       logger.error("received an unexpected message {} from switch {}", msg, sw);
       return Command.CONTINUE;
   }

	/*
	 * Do we need to push packet to the switch? 
	 * push a packet-out to the switch
	 * 
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
	}*/
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
		floodlightProvider.addOFSwitchListener(this);
	}

	
	@Override
	public void switchPortChanged(Long switchId) {
		// TODO Auto-generated method stub
		
	}

	

}

