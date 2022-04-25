package resim.utils;
import com.google.common.collect.Range;
import java.util.concurrent.CompletableFuture;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Trace;
import ghidra.util.database.UndoableTransaction;
import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.model.impl.GdbModelImpl;
import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;

import java.lang.reflect.Field;
import java.lang.Thread;

import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsPlugin;
import ghidra.app.plugin.core.debug.gui.objects.ObjectUpdateService;
import ghidra.app.services.DebuggerModelService;
import ghidra.util.NumericUtilities;

import generic.json.*;
import java.util.*;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.dbg.DebuggerObjectModel;


public class RESimUtils extends Plugin {
        private GdbManagerImpl impl;

        /**
         * Plugin constructor - all plugins must have a constructor with this signature
         * @param tool the pluginTool that this plugin is added to.
         */
        public RESimUtils(PluginTool tool) throws Exception{
                super(tool);
                impl = findGdbManager(tool);
        }
        public GdbManagerImpl getGdbManager() throws Exception {
        	return impl;
        }
        public GdbManagerImpl findGdbManager(PluginTool tool) throws Exception {
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
                return null;
            }
            Field f = GdbModelImpl.class.getDeclaredField("gdb");
            f.setAccessible(true);
            return (GdbManagerImpl) f.get(model);
        }
        private DebuggerObjectsProvider getDebuggerObjectsProvider() throws Exception {
            DebuggerObjectsPlugin objects =
                (DebuggerObjectsPlugin) tool.getService(ObjectUpdateService.class);
            return objects.getProvider(0);
        }
        private DebuggerObjectModel getObjectModel() throws Exception {
            DebuggerObjectsPlugin objects =
                (DebuggerObjectsPlugin) tool.getService(ObjectUpdateService.class);
            DebuggerModelService models = objects.modelService;
            DebuggerObjectModel model = models.getModels()
                .stream()
                .filter(DebuggerObjectModel.class::isInstance)
                .map(DebuggerObjectModel.class::cast)
                .findFirst()
                .orElse(null);
            if (model == null) {
                return null;
            }
            return model;
        }
        public void refreshClient() throws Exception{
	        DebuggerObjectModel object_model = getObjectModel();
	        object_model.invalidateAllLocalCaches();
	        DebuggerObjectsProvider dbo = getDebuggerObjectsProvider();
	        dbo.refresh();
        }


}
