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
package resim.watchmarks;

import java.util.List;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import resim.utils.DebuggerRESimUtilsPlugin;

@PluginInfo( //
		shortDescription = "Debugger watch marks", //
		description = "GUI to list watch marks", //
		category = PluginCategoryNames.DEBUGGER, //
		packageName = DebuggerPluginPackage.NAME, //
		status = PluginStatus.RELEASED, //
		eventsConsumed = {
			TraceActivatedPluginEvent.class, //
			TraceClosedPluginEvent.class, //
		}, //
		servicesRequired = { //
		} // 
)
public class DebuggerWatchMarksPlugin extends AbstractDebuggerPlugin {

	protected DebuggerWatchMarksProvider provider;

	public DebuggerWatchMarksPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		Msg.info(this,  "watch marks plugin init");
		provider = new DebuggerWatchMarksProvider(this);
		provider.getRESimUtils();
		super.init();
		/*
		try {
			provider = new DebuggerWatchMarksProvider(this);
			super.init();
		}catch(Exception e) {
			e.printStackTrace();
		}
		*/
	}

	@Override
	protected void dispose() {
		tool.removeComponentProvider(provider);
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceActivatedPluginEvent) {
			TraceActivatedPluginEvent ev = (TraceActivatedPluginEvent) event;
			provider.coordinatesActivated(ev.getActiveCoordinates());
		}
	}
}
