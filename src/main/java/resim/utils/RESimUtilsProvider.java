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

import java.util.*;
import javax.swing.*;


import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.services.*;

import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.util.Msg;


import agent.gdb.manager.impl.GdbManagerImpl;
import ghidra.framework.plugintool.PluginTool;
public class RESimUtilsProvider extends ComponentProviderAdapter{
    GdbManagerImpl impl=null;

    DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;


    @AutoServiceConsumed
    private DebuggerTraceManagerService traceManager;
    // @AutoServiceConsumed  by method
    private DebuggerModelService modelService;
    // @AutoServiceConsumed via method
    DebuggerStaticMappingService mappingService;
    @AutoServiceConsumed
    private DebuggerListingService listingService; // TODO: Goto pc on double-click
    @AutoServiceConsumed
    private MarkerService markerService; // TODO: Mark non-current frame PCs, too. (separate plugin?)
    @SuppressWarnings("unused")
    private final AutoService.Wiring autoServiceWiring;

    public RESimUtilsProvider(RESimUtilsPlugin plugin)  {
        super(plugin.getTool(), "RESimUtils", plugin.getName());
        //this.plugin = plugin;
        PluginTool tool = plugin.getTool();
        
        this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

        createActions();

        contextChanged();
    }

    protected void createActions() {
        // TODO: Anything?
    }

    @Override
    public JComponent getComponent() {
        return null;
    }

    @AutoServiceConsumed
    public void setModelService(DebuggerModelService modelService) {
        this.modelService = modelService;
    }

    @AutoServiceConsumed
    private void setMappingService(DebuggerStaticMappingService mappingService) {

        this.mappingService = mappingService;

    }

    
}
