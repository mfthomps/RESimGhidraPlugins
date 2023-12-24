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

import java.awt.BorderLayout;

import javax.swing.*;

import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.action.builder.ActionBuilder;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.util.Msg;
import resources.ResourceManager;
import resim.utils.RESimUtilsPlugin;

public class RESimProgramProvider extends ComponentProviderAdapter {
    private final static ImageIcon CLEAR_ICON = ResourceManager.loadImage("images/erase16.png");
    private final static ImageIcon INFO_ICON = ResourceManager.loadImage("images/information.png");

    private JPanel panel;
    private JTextArea textArea;
    private DockingAction clearAction;
    private Program currentProgram;
    private ProgramLocation currentLocation;
    private RESimUtilsPlugin resimUtils;
    public RESimProgramProvider(PluginTool tool, String name) {
        super(tool, name, name);
        resimUtils = RESimUtilsPlugin.getRESimUtils(tool);
        createActions();
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    void clear() {
        currentProgram = null;
        currentLocation = null;
    }

    void locationChanged(Program program, ProgramLocation location) {
        this.currentProgram = program;
        this.currentLocation = location;
        if (isVisible()) {
            //updateInfo();
        }
    }
    protected void revToCursor() {
        Address addr = this.currentLocation.getAddress();
        long offset = addr.getOffset();
        String cmd = "revToAddr("+offset+")";
        try {
            resimUtils.doRESimRefresh(cmd);
        } catch (Exception e) {
            Msg.error(this, RESimUtilsPlugin.getExceptString(e));
        }
        Msg.debug(this, "revToCursor cmd: "+cmd);
    }



    private void createActions() {
        new ActionBuilder("Reverse to Cursor", getName())
        .menuPath(RESimUtilsPlugin.MENU_RESIM, "Reverse to", "&Cursor")
        .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Reverse to")
        .onAction(c -> revToCursor())
        .buildAndInstall(tool);
    }



}
