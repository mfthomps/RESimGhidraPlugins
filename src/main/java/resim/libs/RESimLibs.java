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
            Msg.debug(src,  "op len is 1");
            return null;
        }
        
        InstructionPrototype prototype = instruction.getPrototype();
        List<Object> list =
            prototype.getOpRepresentationList(opIndex, instruction.getInstructionContext());
        if (list == null) {
            Msg.debug(src,  "list null");
            return null;
        }
        DebuggerRegistersProvider registerProvider = (DebuggerRegistersProvider) tool.getComponentProvider(DebuggerResources.TITLE_PROVIDER_REGISTERS);

        if(registerProvider == null) {
            Msg.error(src,  "no register provider");
            return null;
        }
        int sign = 1;
        long sum = 0;
        boolean in_brackets = false;
        boolean found_brackets = false;
        boolean domul = false;
        long preval = 0;
        for(Object o : list){
            //Msg.debug(src,  "type: "+o.getClass()+" "+o.toString());        
          
            //Msg.debug(src, "preval "+preval+" sum "+sum);
            if(!in_brackets){
                if(o instanceof Character){
                    if((Character) o == '['){
                        in_brackets = true;
                    }
                }
            }else{
                if(o instanceof Character){
                    if((Character) o == '+'){
                        sum = sum + preval*sign;
                        sign = 1;
                    }else if ((Character) o == '-'){
                        sum = sum + preval*sign;
                        sign = -1;
                    }else if ((Character) o == '*'){
                        domul = true;
                        //Msg.debug(src, "setting multiply preval was "+preval);
                    }else if ((Character) o == ']'){
                        //Msg.debug(src, "got end bracket preval was "+preval);
                        sum = sum + preval*sign;
                        found_brackets = true;
                        break;
                    }
                }else if(o instanceof Register){
                    Register r = (Register) o;
                    RegisterRow row = registerProvider.getRegisterRow(r);
                    BigInteger regval = row.getValue();
                    preval = regval.longValue();
                }else if(o instanceof Scalar){
                    Scalar s = (Scalar) o;
                    if(domul){
                        preval = preval * s.getSignedValue();
                        domul = false;
                        //Msg.debug(src, "did mul, preval now "+preval);
                    }else{
                        preval = s.getSignedValue();
                    }
                }
            }
        }
        if(found_brackets){
            retval = addr(tool, sum);
        }
         
        return retval;

    }
}
