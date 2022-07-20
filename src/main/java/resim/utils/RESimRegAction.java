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
package resim.utils;

import java.awt.event.KeyEvent;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
/**

 * Action in RESimUtils.
 */
public class RESimRegAction extends ListingContextAction {
    /** the plugin associated with this action. */
    RESimUtilsPlugin plugin;
    String cmd;
    RESimProvider refresh;

    /**
     * Create a new action, to create a function at the current location with a selection
     * 
     * @param string  name of the action
     * @param resimUtils does checking for this action

     */
    public RESimRegAction(String name, String cmd, RESimUtilsPlugin plugin, RESimProvider refresh) {
        super(name, plugin.getName());
        this.plugin = plugin;
        this.cmd = cmd;
        this.refresh = refresh;

            // top-level item usable most places
            setPopupMenuData(
                new MenuData(new String[] { "Resim", name }, null, RESimUtilsPlugin.RESIM_MENU_SUBGROUP,
                    MenuData.NO_MNEMONIC, RESimUtilsPlugin.RESIM_SUBGROUP_BEGINNING));


        setEnabled(true);
    }
    private Object getOperand(OperandFieldLocation loc, Instruction instruction) {
        int opIndex = loc.getOperandIndex();
        Object[] operands = instruction.getOpObjects(opIndex);
        if (operands.length == 1) {
            return operands[0];
        }

        InstructionPrototype prototype = instruction.getPrototype();
        List<Object> list =
            prototype.getOpRepresentationList(opIndex, instruction.getInstructionContext());
        if (list == null) {
            return null;
        }
        // make sure operand sub-opIndex is in bounds
        int subOpIndex = loc.getSubOperandIndex();
        if (subOpIndex < 0 || subOpIndex >= list.size()) {
            return null;
        }
        return list.get(subOpIndex);
    }
    /**
     * Method called when the action is invoked.
     * @param ActionEvent details regarding the invocation of this action
     */
    @Override
    public void actionPerformed(ListingActionContext context) {
        String full_cmd = null;
        ProgramLocation programLocation = context.getLocation();
        Address a = programLocation.getAddress();
        Instruction instruction = context.getProgram().getListing().getInstructionAt(a);
        OperandFieldLocation operandLocation = (OperandFieldLocation) programLocation;
        Object op = getOperand(operandLocation, instruction);
        if(op != null) {
            Msg.debug(this,  "op is "+op.getClass()+" value  "+op.toString());
            if(op instanceof Register) {
                full_cmd = this.cmd+"('"+op.toString()+"')";
            }
        }

        if(full_cmd != null) {
            Msg.debug(this, "In actionPerformed will do cmd: "+full_cmd);
            try {
                CompletableFuture<String> refresh_future = plugin.doRESimRefresh(full_cmd);
                refresh_future.thenApply(result -> {
                    Msg.debug(this, "actionPerformed, did cmd, resim says "+result);
                    //plugin.refreshClient(true);
                    if(this.refresh != null){
                        this.refresh.refresh();
                    }
                    return result;
                });
            } catch (Exception e) {
                Msg.error(this, plugin.getExceptString(e));
            }
            Msg.debug(this, "back from actionPerformed cmd: "+cmd);
        }
    }

    @Override
    protected boolean isEnabledForContext(ListingActionContext context) {
        return true;
        //return this.funcPlugin.isCreateFunctionAllowed(context, allowExisting, createThunk);
    }

}
