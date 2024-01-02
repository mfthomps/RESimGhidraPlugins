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
package resim.hover;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import javax.swing.JComponent;

import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;
import agent.gdb.model.impl.GdbModelImpl;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.codebrowser.hover.ListingHoverService;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsPlugin;
import ghidra.app.plugin.core.debug.gui.objects.ObjectUpdateService;
import ghidra.app.plugin.core.hover.AbstractConfigurableHover;
import ghidra.app.services.DebuggerModelService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import resim.libs.RESimLibs;

public class ReferenceOperandListingHover extends AbstractConfigurableHover 
		implements ListingHoverService {
    // TBD determine reasonable priority
	private static final int PRIORITY = 101;
	private static final String NAME = "Referencee Operand Display";
	private static final String DESCRIPTION =
		"Display content of referenced memory.";
	private Trace currentTrace;
	private GdbManagerImpl impl;
	public ReferenceOperandListingHover(PluginTool tool) {
		super(tool, PRIORITY);
	}
    /**
     * Get the instance of the GDBManagerImpl using tool.getService 
     * @return The instance.
     */
    public GdbManagerImpl getGdbManager() throws Exception {
        GdbManagerImpl retval=null;
        if(this.impl == null) {
            DebuggerObjectsPlugin objects = 
                (DebuggerObjectsPlugin) tool.getService(ObjectUpdateService.class);
            DebuggerModelService models = objects.modelService;
            GdbModelImpl model = models.getModels()
                .stream()
                .filter(GdbModelImpl.class::isInstance)
                .map(GdbModelImpl.class::cast)
                .findFirst()
                .orElse(null);
            if (model == null) {
                Msg.info(this, "Failed to get GdbManager, model is null");
                return null;
            }
            java.lang.reflect.Field f = GdbModelImpl.class.getDeclaredField("gdb");
            f.setAccessible(true);
            this.impl = (GdbManagerImpl) f.get(model);
            if(this.impl == null) {
                Msg.info(this, "Failed to get GdbManager");
            }
        }
        retval = impl;
        
        return retval;
    }
    public Trace getCurrentTrace() {
        DebuggerTraceManagerService traces =
                tool.getService(DebuggerTraceManagerService.class);
        if(traces == null) {
            return null;
        }
        int failcount = 0;
        while(currentTrace == null){
            currentTrace = traces.getCurrentTrace();
            if(currentTrace == null){
                Msg.debug(this,"no current trace, wait a sec");
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
        return currentTrace;
    }
    public CompletableFuture<String> doGdbCmd(String full_cmd) {
        /**
         * Send a command to the GDB console.
         * @param cmd Command to execute
         * @return The response from GDB
         */
        if(impl == null) {
            try {
                impl = getGdbManager();
                Msg.debug(this,  "doGdbCmd set impl");
            } catch (Exception e) {
                // TODO Auto-generated catch block
                Msg.error(this,  "doGdbCmd failed to get gdb manager");
                e.printStackTrace();
            }
            if(impl == null) {
                Msg.error(this,  "doGdbCmd: Failed to get gdb manager");
                return null;
            }
        }
        return impl.consoleCapture(full_cmd, CompletesWithRunning.CANNOT);
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
	public JComponent getHoverComponent(Program program, ProgramLocation programLocation,
			FieldLocation fieldLocation, Field field) {

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
		if(currentTrace == null) {
		    return null;
		}
		OperandFieldLocation operandLocation = (OperandFieldLocation) programLocation;
		Address memReference  = RESimLibs.getMemReference(this, tool, operandLocation, instruction);
		if (memReference == null) {
			return null;
		}
		String cmd = "x "+memReference.getOffset();
		Msg.debug(this,  "gdb cmd is "+cmd);
		CompletableFuture<String> gdbret = doGdbCmd(cmd);

		if(gdbret == null) {
		    return null;
		}
		String rval = null;
		try {
            rval = gdbret.get();
        } catch (InterruptedException | ExecutionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
		Msg.debug(this,"gdb returned "+rval);
		String formatted =
			formatString(instruction.getProgram(), rval);
		Msg.debug(this, "hovering memReference "+memReference.toString());
		return createTooltipComponent(formatted);
	}
	protected String formatString(Program program, String value) {
           StringBuilder sb = new StringBuilder(HTMLUtilities.HTML);
           sb.append("<hr>");
           sb.append("<table>");
           sb.append(value);
           sb.append("</table>");

           return sb.toString();
    }


}
