package resim.utils;

import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;
import agent.gdb.model.impl.GdbModelImpl;

import java.lang.reflect.Field;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsPlugin;
import ghidra.app.plugin.core.debug.gui.objects.ObjectUpdateService;
import ghidra.app.services.DebuggerModelService;


import ghidra.framework.plugintool.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class RESimUtils extends Plugin {
        private PluginTool tool;
        private Program program;
        /**
         * Plugin constructor - all plugins must have a constructor with this signature
         * @param tool the pluginTool that this plugin is added to.
         */
        public RESimUtils(PluginTool tool, Program program) throws Exception{
                super(tool);
                this.tool = tool;
                this.program = program;
                tool.addPlugin(this);
        }

        public GdbManagerImpl getGdbManager() throws Exception {
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
            Field f = GdbModelImpl.class.getDeclaredField("gdb");
            f.setAccessible(true);
            GdbManagerImpl retval = (GdbManagerImpl) f.get(model);
            if(retval == null) {
            	Msg.info(this, "Failed to get GdbManager");
            }
            return retval;
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
    	public Address addr(long addr) {
    		AddressFactory addrFactory = this.program.getAddressFactory();
    		return addrFactory.getConstantAddress(addr);
    	}
    	public String doRESim(String cmd, GdbManagerImpl impl) throws Exception {
    		String retval = null;
    		String full_cmd = "monitor @cgc."+cmd;
            CompletableFuture<String> future = impl.consoleCapture(full_cmd, CompletesWithRunning.CANNOT);
            try {
            	retval = future.get();
    		} catch (InterruptedException e) {
    			// TODO Auto-generated catch block
    			e.printStackTrace();
    			throw new Exception("Failed resim command, interruptedException:"+cmd);
    		} catch (ExecutionException e) {
    			// TODO Auto-generated catch block
    			e.printStackTrace();
    			throw new Exception("Failed to resim command, execution exception:"+cmd);
    		}
            if(retval != null) {
            	refreshClient();
            }
            return retval;
    	}

}
