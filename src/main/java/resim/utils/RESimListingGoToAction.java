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
import java.util.concurrent.CompletableFuture;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.services.DebuggerListingService;
import ghidra.app.services.DebuggerModelService;
import ghidra.app.services.GoToService;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resim.libs.RESimLibs;
/**

 *  NOT USED -- artifact of early testing
 */
public class RESimListingGoToAction extends ListingContextAction {
    /** the plugin associated with this action. */
    RESimUtilsPlugin plugin;
    String cmd;
    @AutoServiceConsumed
    private DebuggerListingService listingService;
    /**
     * Create a new action, to create a function at the current location with a selection
     * 
     * @param string  name of the action
     * @param resimUtils does checking for this action

     */
    public RESimListingGoToAction(String name, RESimUtilsPlugin plugin) {
        super(name, plugin.getName());
        this.plugin = plugin;
        setPopupMenuData(
                new MenuData(new String[] { "Resim", name }, null, RESimUtilsPlugin.RESIM_MENU_SUBGROUP,
                    MenuData.NO_MNEMONIC, RESimUtilsPlugin.RESIM_SUBGROUP_BEGINNING));
        setEnabled(true);
    }

    /**
     * Method called when the action is invoked.
     * @param ActionEvent details regarding the invocation of this action
     */
    @Override
    public void actionPerformed(ListingActionContext context) {
        Address entry = null;
        AddressSetView body = null;
        ProgramLocation loc = context.getLocation();
        Address a = loc.getAddress();
        Instruction instruction = context.getProgram().getListing().getInstructionAt(a);
        OperandFieldLocation operandLocation = (OperandFieldLocation) loc;
        Address memref = RESimLibs.getMemReference(this, plugin.getTool(), operandLocation, instruction);
        if(memref != null) {
            GoToService gotoService = plugin.getTool().getService(GoToService.class);

            listingService = plugin.getTool().getService(DebuggerListingService.class);
            if(listingService == null) {
                Msg.debug(this,  "yep, still null");
            }else {

                listingService.goTo(memref, true);
                Msg.debug(this,  "tried listing service");
            }
        }else {
            Msg.debug(this, "no mem ref found.");
        }
       
    }

    @Override
    protected boolean isEnabledForContext(ListingActionContext context) {
        return true;
        //return this.funcPlugin.isCreateFunctionAllowed(context, allowExisting, createThunk);
    }

}
