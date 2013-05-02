package net.floodlightcontroller.anomalydetector;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.web.serializers.IPv4Serializer;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;


import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.Wildcards;
import org.openflow.protocol.Wildcards.Flag;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class RuleMaker 
{

	protected OFMatch FlowMatch;
	protected OFFlowMod rule;
	
	protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 20; // in seconds
    protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite
    protected static short FLOWMOD_PRIORITY  = 1;
	
    protected Map<String, OFFlowMod> Stats = new HashMap<String, OFFlowMod>();
    protected Map<Long, Short> MacToPort;
    protected IFloodlightProviderService FloodlightProvider;
    private DetectionUnit Detector;
    protected static Logger Logger = LoggerFactory.getLogger(RuleMaker.class);;
    
    public RuleMaker(IFloodlightProviderService FloodlightProvider, DetectionUnit Detector)
	{
		this.FloodlightProvider = FloodlightProvider;
		this.Detector = Detector;
		this.MacToPort = new HashMap<Long, Short>();
	}
	
	
	 private void CreateFlowMod(IOFSwitch sw, short command, int bufferId,OFMatch match, short outPort)
	    {
	    	long Cookie = (long)(this.Detector.ClusterID);
	    	OFFlowMod flowMod = (OFFlowMod) this.FloodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
	    	this.Detector.AddCluster(match);
	    	
	    	flowMod.setMatch(match);
	        flowMod.setCookie(Cookie);
	        flowMod.setCommand(command);
	        
	      //  flowMod.setIdleTimeout(LearningSwitch.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
	        flowMod.setHardTimeout(RuleMaker.FLOWMOD_DEFAULT_HARD_TIMEOUT);
	        flowMod.setPriority(RuleMaker.FLOWMOD_PRIORITY);
	        flowMod.setBufferId(bufferId);
	        flowMod.setOutPort((command == OFFlowMod.OFPFC_DELETE) ? outPort : OFPort.OFPP_NONE.getValue());
	        flowMod.setFlags((command == OFFlowMod.OFPFC_DELETE) ? 0 : (short) (1 << 0)); // OFPFF_SEND_FLOW_REM

	        flowMod.setActions(Arrays.asList((OFAction) new OFActionOutput(outPort, (short) 0xffff)));
	        flowMod.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));

	        if (RuleMaker.Logger.isTraceEnabled()) 
	        {
	        	RuleMaker.Logger.trace("{} {} flow mod {}", 
	                      new Object[]{ sw, (command == OFFlowMod.OFPFC_DELETE) ? "deleting" : "adding", flowMod });
	        }
	     
	        try 
	        {
	            sw.write(flowMod, null);
	        } 
	        catch (IOException e)
	        {
	        	RuleMaker.Logger.error("Failed to write {} to switch {}", new Object[]{ flowMod, sw }, e);
	        }
	    }

	    
	 public Command ProcessNewFlow(IOFSwitch sw, OFPacketIn pi) 
	    {
	        // Read in packet data headers by using OFMatch
	        OFMatch match = new OFMatch();
	        
	        match.loadFromPacket(pi.getPacketData(), pi.getInPort());
	        Long sourceMac = Ethernet.toLong(match.getDataLayerSource());
	        Long destMac = Ethernet.toLong(match.getDataLayerDestination());
	       
	        if (!this.MacToPort.containsKey(sourceMac))
	        {
	        	this.MacToPort.put(sourceMac, pi.getInPort());
	        }
	        Short outPort = this.MacToPort.get(destMac);
	        if (outPort == null) 
	        {
	        	this.pushPacket(sw, match, pi, OFPort.OFPP_FLOOD.getValue());
	        }
	        else
	        { 
	        	
	        	match.setWildcards(Wildcards.FULL
	        		//.matchOn(Flag.IN_PORT)
	        		.matchOn(Flag.DL_TYPE)
	        		.matchOn(Flag.DL_DST)
	        		.matchOn(Flag.DL_SRC)
	        		.matchOn(Flag.NW_PROTO)
	        		.withNwSrcMask(8).withNwDstMask(32));
        
	        	    this.pushPacket(sw, match, pi, outPort);
	                this.CreateFlowMod(sw, OFFlowMod.OFPFC_ADD, OFPacketOut.BUFFER_ID_NONE, match, outPort);
	                this.CreateFlowMod(sw, OFFlowMod.OFPFC_ADD, -1, match.clone()
	                    .setDataLayerSource(match.getDataLayerDestination())
	                    .setDataLayerDestination(match.getDataLayerSource())
	                    .setNetworkSource(match.getNetworkDestination())
	                    .setNetworkDestination(match.getNetworkSource())
	                    .setTransportSource(match.getTransportDestination())
	                    .setTransportDestination(match.getTransportSource())
	                    .setNetworkProtocol(match.getNetworkProtocol())
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
	            if (RuleMaker.Logger.isDebugEnabled()) 
	            {
	            	RuleMaker.Logger.debug("Attempting to do packet-out to the same " + 
	                          "interface as packet-in. Dropping packet. " + 
	                          " SrcSwitch={}, match = {}, pi={}", 
	                          new Object[]{sw, match, pi});
	                return;
	            }
	        }

	        if (RuleMaker.Logger.isTraceEnabled()) 
	        {
	        	RuleMaker.Logger.trace("PacketOut srcSwitch={} match={} pi={}", 
	                      new Object[] {sw, match, pi});
	        }

	        OFPacketOut po = (OFPacketOut) this.FloodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT);

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
	        	RuleMaker.Logger.error("Failure writing packet out", e);
	        }
	    }
	
}
