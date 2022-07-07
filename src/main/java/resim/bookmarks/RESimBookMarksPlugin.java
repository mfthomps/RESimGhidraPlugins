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
package resim.bookmarks;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

@PluginInfo( //
        shortDescription = "RESim bookmarks", //
        description = "GUI to list and create RESim bookmarks and skip to selected execution points", //
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
public class RESimBookMarksPlugin extends AbstractDebuggerPlugin {

    protected RESimBookMarksProvider provider;

    public RESimBookMarksPlugin(PluginTool tool) {
        super(tool);
    }

    @Override
    protected void init() {
        Msg.info(this,  "book marks plugin init");
        provider = new RESimBookMarksProvider(this);
        super.init();

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
