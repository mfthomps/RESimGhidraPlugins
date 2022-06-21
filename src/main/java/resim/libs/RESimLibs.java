package resim.libs;

import java.math.BigInteger;
import java.util.List;

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.register.DebuggerRegistersProvider;
import ghidra.app.plugin.core.debug.gui.register.RegisterRow;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.util.OperandFieldLocation;
import ghidra.trace.model.Trace;
import ghidra.util.Msg;

public class RESimLibs {
    public static Trace getCurrentTrace(Object src, PluginTool tool) {
        DebuggerTraceManagerService traces =
                tool.getService(DebuggerTraceManagerService.class);
        if(traces == null) {
            return null;
        }
        int failcount = 0;
        Trace retval = null;
        while(retval == null){
            retval = traces.getCurrentTrace();
            if(retval == null){
                Msg.debug(src,"no current trace, wait a sec");
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                failcount++;
                if(failcount > 10){
                    return null;
                }
            }
        }
        return retval;
    }
    public static boolean isbrackets(List<Object>list) {
        boolean retval = false;
        if(list.get(0) instanceof Character && list.get(list.size() -1) instanceof Character) {
            if((Character)list.get(0) == '[' && (Character)list.get(list.size()-1) == ']') {
                retval = true;
            }
        }else {
            Msg.debug(null,  "not brackets");
        }
        return retval;
    }
    public static Address addr(PluginTool tool, long offset) {
        Trace currentTrace = getCurrentTrace(null, tool);
        AddressSpace dynRam = currentTrace.getBaseAddressFactory().getDefaultAddressSpace();
        return dynRam.getAddress(offset);
    }
    public static Address getMemReference(Object src, PluginTool tool, OperandFieldLocation loc, Instruction instruction) {
        Address retval = null;
        int opIndex = loc.getOperandIndex();
        Object[] operands = instruction.getOpObjects(opIndex);
        if (operands.length == 1) {
            //return operands[0];
            return null;
        }
        
        InstructionPrototype prototype = instruction.getPrototype();
        List<Object> list =
            prototype.getOpRepresentationList(opIndex, instruction.getInstructionContext());
        if (list == null) {
            return null;
        }
        DebuggerRegistersProvider registerProvider = null;
        if(isbrackets(list)) {
            Msg.debug(src,  "is brackets");
            if(list.get(1) instanceof Register) {
                Register r = (Register) list.get(1);
                registerProvider = (DebuggerRegistersProvider) tool.getComponentProvider(DebuggerResources.TITLE_PROVIDER_REGISTERS);

                if(registerProvider == null) {
                    Msg.error(src,  "no register provider");
                    return null;
                }
                
                RegisterRow row = registerProvider.getRegisterRow(r);
                
                BigInteger regval = row.getValue();
                if(list.get(4) instanceof Scalar) {
                    Scalar s = (Scalar) list.get(4);
                    Long sval = s.getSignedValue();
                    Long offset = regval.longValue() + sval;
                    Msg.debug(src, "scalar value "+sval+" regval "+regval+" offset"+ offset);
                    retval = addr(tool, offset);

                }else {
                    Msg.debug(src,  "list(4) not scalar, is "+list.get(4).getClass());
                }
            }
            
        }
        return retval;

    }
}
