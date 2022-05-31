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

import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
/**

 * Action in RESimUtils.
 */
class RevToCursorAction extends ListingContextAction {
    /** the plugin associated with this action. */
    RESimUtilsPlugin plugin;



    /**
     * Create a new action, to create a function at the current location with a selection
     * 
     * @param string  name of the action
     * @param resimUtils does checking for this action

     */
    public RevToCursorAction(String name, RESimUtilsPlugin plugin) {
        super(name, plugin.getName());
        this.plugin = plugin;


            // top-level item usable most places
            setPopupMenuData(
                new MenuData(new String[] { name }, null, RESimUtilsPlugin.RESIM_MENU_SUBGROUP,
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

        if (context.hasSelection()) {
            body = context.getSelection();
            entry = body.getMinAddress();
        }
        else {
            entry = context.getAddress();
        }
         
        if (entry == null) {
            return;
        }
        long addr = entry.getOffset();
        String cmd = "revToAddr("+addr+")";
        Msg.debug(this, "In actionPerformed will do cmd: "+cmd);
        try {
            plugin.doRESimRefresh(cmd);
        } catch (Exception e) {
            Msg.error(this, plugin.getExceptString(e));
        }
        Msg.debug(this, "back from actionPerformed cmd: "+cmd);
    }

    @Override
    protected boolean isEnabledForContext(ListingActionContext context) {
        return true;
        //return this.funcPlugin.isCreateFunctionAllowed(context, allowExisting, createThunk);
    }

}
