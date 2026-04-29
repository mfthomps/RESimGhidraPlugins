/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 *  NOTE this is no longer used because Ghidra now has a register value hover function.
 */
package resim.hover;

import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.codebrowser.hover.ListingHoverService;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.register.DebuggerRegistersProvider;
import ghidra.app.plugin.core.debug.gui.register.RegisterRow;
import ghidra.app.plugin.core.hover.AbstractConfigurableHover;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import resim.utils.RESimUtilsPlugin;

public class RegisterOperandListingHover extends AbstractConfigurableHover implements ListingHoverService {

    private static final int PRIORITY = 100;
    private static final String NAME = "Register Operand Display";
    private static final String DESCRIPTION = "Display content of register.";
    private DebuggerRegistersProvider registerProvider = null;
    private Trace currentTrace;
    private RESimUtilsPlugin utilsPlugin = null;

    public RegisterOperandListingHover(PluginTool tool) {
        super(tool, PRIORITY);
    }

    public Trace getCurrentTrace() {
        DebuggerTraceManagerService traces = tool.getService(DebuggerTraceManagerService.class);
        if (traces == null) {
            return null;
        }
        int failcount = 0;
        while (currentTrace == null) {
            currentTrace = traces.getCurrentTrace();
            if (currentTrace == null) {
                Msg.debug(this, "no current trace, wait a sec");
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                failcount++;
                if (failcount > 10) {
                    return null;
                }
            }
        }
        return currentTrace;
    }

    @Override
    protected String getName() {
        return NAME;
    }

    @Override
    protected String getDescription() {
        return DESCRIPTION;
    }

    @Override
    protected String getOptionsCategory() {
        return GhidraOptions.CATEGORY_BROWSER_POPUPS;
    }

    @Override
    public JComponent getHoverComponent(Program program, ProgramLocation programLocation, FieldLocation fieldLocation,
            Field field) {
        Msg.debug(this, "getHoverComponent");
        if (!enabled || programLocation == null) {
            return null;
        }

        if (!(programLocation instanceof OperandFieldLocation)) {
            return null;
        }

        Address a = programLocation.getAddress();
        Instruction instruction = program.getListing().getInstructionAt(a);
        if (instruction == null) {
            return null;
        }
        currentTrace = getCurrentTrace();
        if (currentTrace == null) {
            return null;
        }

        OperandFieldLocation operandLocation = (OperandFieldLocation) programLocation;
        Register reg = getRegister(operandLocation, instruction);
        if (reg != null) {
            Msg.debug(this, "Register is " + reg.getName());
            if(utilsPlugin == null) {
	        utilsPlugin = RESimUtilsPlugin.getRESimUtils(tool);
	    }
            Long regval = utilsPlugin.getRegValue(reg.getName());
            if(regval != null){
                String disp = reg.getName() + " : " + Long.toHexString(regval);
                String formatted = formatString(instruction.getProgram(), disp);
                return createTooltipComponent(formatted);
            }else{
                Msg.debug(this, "Got null from getRegValue for "+reg.toString());
                return null;
            }
        } else {
            return null;
        }
    }

    protected String formatString(Program program, String value) {
        StringBuilder sb = new StringBuilder(HTMLUtilities.HTML);
        sb.append("<hr>");
        sb.append("<table>");
        sb.append(value);
        sb.append("</table>");

        return sb.toString();
    }

    protected Register getRegister(OperandFieldLocation loc, Instruction instruction) {

        registerProvider = (DebuggerRegistersProvider) tool
                .getComponentProvider(DebuggerResources.TITLE_PROVIDER_REGISTERS);

        int opIndex = loc.getOperandIndex();
        Object[] operands = instruction.getOpObjects(opIndex);
        Register reg = null;
        if (operands.length == 1) {
            if (operands[0] instanceof Register) {
                reg = (Register) operands[0];
            }
        } else {
            InstructionPrototype prototype = instruction.getPrototype();
            List<Object> list = prototype.getOpRepresentationList(opIndex, instruction.getInstructionContext());
            if (list == null) {
                return null;
            }
            int subIndex = loc.getSubOperandIndex();
            Object subob = list.get(subIndex);
            if (subob instanceof Register) {
                reg = (Register) subob;
            }
        }
        return reg;
    }

    protected Long getRegValue(Register reg) {
        Long retval = null;

        if (reg != null) {
            RegisterRow row = registerProvider.getRegisterRow(reg);
            if(row != null){
                BigInteger regval = row.getValue();
                retval = regval.longValue();
            }else{
                Msg.debug(this, "getRegValue row null for reg "+reg.toString());
            }
        }
        return retval;

    }

}
