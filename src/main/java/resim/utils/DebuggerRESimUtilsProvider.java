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

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.HashMap;
import java.util.function.*;

import javax.swing.*;


import docking.ActionContext;
import docking.WindowPosition;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.*;

import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;

import ghidra.trace.model.*;

import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.Msg;


import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;
import agent.gdb.manager.impl.GdbManagerImpl;
import ghidra.framework.plugintool.PluginTool;

import resim.utils.DebuggerRESimUtilsPlugin;
import resim.utils.Json;
import resim.utils.RESimProvider;
public class DebuggerRESimUtilsProvider extends ComponentProviderAdapter{
	GdbManagerImpl impl=null;


	protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getTrace(), b.getTrace())) {
			return false;
		}
		if (!Objects.equals(a.getThread(), b.getThread())) {
			return false;
		}
		if (!Objects.equals(a.getTime(), b.getTime())) {
			return false;
		}
		if (!Objects.equals(a.getFrame(), b.getFrame())) {
			return false;
		}
		return true;
	}



	//private final DebuggerStackPlugin plugin;

	// Table rows access these for function name resolution
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




	private JPanel mainPanel = new JPanel(new BorderLayout());

	private DebuggerRESimUtilsPlugin resimUtils; 

	public DebuggerRESimUtilsProvider(DebuggerRESimUtilsPlugin plugin)  {
		super(plugin.getTool(), "RESimUtils", plugin.getName());
		//this.plugin = plugin;
	    PluginTool tool = plugin.getTool();

		
		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);


		createActions();

		setVisible(true);
		contextChanged();
	}
    protected void getRESimUtils() {
	    resimUtils = null;
	    
	    List<Plugin> pluginList = tool.getManagedPlugins();
	    for (Plugin p : pluginList) {
	    	if(p.getClass() == DebuggerRESimUtilsPlugin.class) {
	    		resimUtils = (DebuggerRESimUtilsPlugin) p;
	    	}
	    }
	    if(resimUtils == null) {
	    	Msg.error(this,  "Failed to find RESimUtils in tool");
	    }
    }






	protected void createActions() {
		// TODO: Anything?
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}







	protected String computeSubTitle() {
		TraceThread curThread = current.getThread();
		return curThread == null ? "" : curThread.getName();
	}

	protected void updateSubTitle() {
		setSubTitle(computeSubTitle());
	}



	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}
		current = coordinates;

		updateSubTitle();
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
