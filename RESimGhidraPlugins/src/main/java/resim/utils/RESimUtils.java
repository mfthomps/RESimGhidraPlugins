package resim.utils;

import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;
import agent.gdb.model.impl.GdbModelImpl;

import java.lang.reflect.Field;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsPlugin;
import ghidra.app.plugin.core.debug.gui.objects.ObjectUpdateService;
import ghidra.app.plugin.core.function.RecentlyUsedAction;
import ghidra.app.services.DebuggerModelService;


import ghidra.framework.plugintool.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Trace;
import ghidra.util.database.UndoableTransaction;

import java.lang.Thread;
import com.google.common.collect.Range;

public class RESimUtils extends Plugin {
        private PluginTool tool;
        private Program program;
        private GdbManagerImpl impl;
    	public final static String RESIM_MENU_SUBGROUP = "RESim";
    	public final static String RESIM_MENU_PULLRIGHT = "RESim";
    	public final static String RESIM_SUBGROUP_MIDDLE = "M_Middle";
    	public final static String RESIM_SUBGROUP_BEGINNING = "Begin";
    	private RevToCursorAction revToCursorAction;


        /**
         * Plugin constructor - all plugins must have a constructor with this signature
         * @param tool the pluginTool that this plugin is added to.
         */
        public RESimUtils(PluginTool tool, Program program) throws Exception{
                super(tool);
                this.tool = tool;
                this.program = program;
                tool.addPlugin(this);
                this.impl = null;
        		createActions();

        }

        public GdbManagerImpl getGdbManager() throws Exception {
        	GdbManagerImpl retval=null;
        	if(impl == null) {
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
	            retval = (GdbManagerImpl) f.get(model);
	            if(retval == null) {
	            	Msg.info(this, "Failed to get GdbManager");
	            }
        	}else {
        		retval = impl;
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
    		// Get an address in the program memory space.
            AddressSpace statRam = program.getAddressFactory().getDefaultAddressSpace();
            return statRam.getAddress(addr);
    	}
    	public String doRESim(String cmd) throws Exception{
    		GdbManagerImpl myimpl = getGdbManager();
    		return doRESim(cmd, myimpl);
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
            Msg.info(this,  "Done with doRESim");
            return retval;
    	}
        protected void doMapping(Long start, Long end) throws Exception{
            Msg.debug(this,"in doMapping\n");
            Long length = end - start;
            DebuggerStaticMappingService mappings =
                    tool.getService(DebuggerStaticMappingService.class);
            DebuggerTraceManagerService traces =
                    tool.getService(DebuggerTraceManagerService.class);

            Trace currentTrace = null;
            int failcount = 0;
            while(currentTrace == null){
                currentTrace = traces.getCurrentTrace();
                if(currentTrace == null){
                	Msg.debug(this,"no current trace, wait a sec");
                    Thread.sleep(1000);
                    failcount++;
                    if(failcount > 10){
                        return;
                    }
                }
            }
            AddressSpace dynRam = currentTrace.getBaseAddressFactory().getDefaultAddressSpace();
            AddressSpace statRam = program.getAddressFactory().getDefaultAddressSpace();

            try (UndoableTransaction tid =
                    UndoableTransaction.start(currentTrace, "Add Mapping", true)) {
                    mappings.addMapping(
                            new DefaultTraceLocation(currentTrace, null, Range.atLeast(0L),
                                    dynRam.getAddress(start)),
                            new ProgramLocation(program, statRam.getAddress(start)),
                            length, false);
            }
            Msg.debug(this,"did mapping for start "+String.format("0x%08X", start)+" length "+length);
    }
        protected void parseSO(String all_string){
            Msg.debug(this,"in parseSO\n");
            Object obj = Json.getJson(all_string);
            if(obj == null){
            	Msg.debug(this,"Error getting json of somap");
                return;
            }
            java.util.HashMap<Object, Object> somap = (java.util.HashMap<Object, Object>) obj;

            Msg.debug(this,"did hash parseSO\n");
            Msg.debug(this,"size of hashmap is "+ somap.size());

            Long pid_o = (Long) somap.get("group_leader");
            Msg.debug(this,"in parseSO pid_o is "+pid_o);
            Long start = (Long) somap.get("prog_start");
            Long end = (Long) somap.get("prog_end");
            try{
                doMapping(start, end);
                Msg.debug(this,"did call doMapping");
            }catch(java.lang.Exception e){
            	Msg.debug(this,"Error thrown by doMapping\n"+e.toString());
                e.printStackTrace();
            }
        }
        public void doMapping() throws Exception{
            String cmd = "getSOMap()";
            String soJson = doRESim(cmd);
            parseSO(soJson);

        }
    	private void createActions() {


    		// we want to put all function pull-right menus in the same group
    		tool.setMenuGroup(new String[] { RESIM_MENU_PULLRIGHT }, RESIM_MENU_SUBGROUP,
    			RESIM_SUBGROUP_MIDDLE);
    		revToCursorAction = new RevToCursorAction("Rev to Cursor", this);
    		tool.addAction(revToCursorAction);
    	}
}
