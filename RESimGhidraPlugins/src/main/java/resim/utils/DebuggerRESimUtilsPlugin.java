package resim.utils;

import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;
import agent.gdb.model.impl.GdbModelImpl;
import docking.action.builder.ActionBuilder;

import java.lang.reflect.Field;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.ArrayList;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsPlugin;
import ghidra.app.plugin.core.debug.gui.objects.ObjectUpdateService;
import ghidra.app.plugin.core.function.RecentlyUsedAction;
import ghidra.app.services.BlockModelService;
import ghidra.app.services.DebuggerModelService;


import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Trace;
import ghidra.util.database.UndoableTransaction;
import resim.restack.DebuggerREStackProvider;
import resim.restack.DebuggerREStackPlugin;
import resim.watchmarks.DebuggerWatchMarksProvider;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.Thread;
import com.google.common.collect.Range;
@PluginInfo( //
		shortDescription = "RESim Utils", //
		description = "Manage RESim utils", //
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
public class DebuggerRESimUtilsPlugin extends Plugin {
        private PluginTool tool;
        private Program program;
        private GdbManagerImpl impl;
    	public final static String RESIM_MENU_SUBGROUP = "RESim";
    	public final static String RESIM_MENU_PULLRIGHT = "RESim";
    	public final static String RESIM_SUBGROUP_MIDDLE = "M_Middle";
    	public final static String RESIM_SUBGROUP_BEGINNING = "Begin";
    	private RevToCursorAction revToCursorAction;
    	private ArrayList<RESimProvider> refreshProviders;
    	public final static String MENU_RESIM = "&RESim";
    	protected DebuggerRESimUtilsProvider provider;
 
        /**
         * Plugin constructor - all plugins must have a constructor with this signature
         * @param tool the pluginTool that this plugin is added to.
         */
        public DebuggerRESimUtilsPlugin(PluginTool tool){
                super(tool);
                this.tool = tool;
                this.program = null;
                this.impl = null;
                Msg.info(this,  "in resimutils plugin");
        		//createActions();
        		refreshProviders = new ArrayList<RESimProvider>();
                Msg.info(this,  "did providers refresh");

        		if(program != null) {
        			Msg.info(this,  "Constructor defined refreshProviders, load other plugins");
        			loadOtherPlugins();
        		}else {
        			Msg.info(this, "Constructor, program is null");
        		}
        }
    	@Override
    	protected void init() {
    		Msg.info(this,  "in init");
    		provider = new DebuggerRESimUtilsProvider(this);

    		createActions();


    	}
    	public static String getExceptString(Exception e) {
			  StringWriter sw = new StringWriter();
			  e.printStackTrace(new PrintWriter(sw));
			  String stackTrace = sw.toString();
			  return stackTrace;
    	}
        protected void firstFun() {
        	
        }
        protected void secondFun() {
        	
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
	        for(RESimProvider provider : refreshProviders) {
	        	provider.refresh();
	        }
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
    	public String doRESimRefresh(String cmd, GdbManagerImpl impl) throws Exception {
    		String retval = doRESim(cmd, impl);
    		if(retval != null) {
    			refreshClient();
    		}
    		return retval;
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
    		loadOtherPlugins();

        }
    	private void createActions() {


    		// we want to put all function pull-right menus in the same group
    		tool.setMenuGroup(new String[] { RESIM_MENU_PULLRIGHT }, RESIM_MENU_SUBGROUP,
    			RESIM_SUBGROUP_MIDDLE);
    		revToCursorAction = new RevToCursorAction("Rev to Cursor", this);
    		tool.addAction(revToCursorAction);
    		
    		tool.setMenuGroup(new String[] { MENU_RESIM, "first" }, "first", "second");
        	new ActionBuilder("Graph To/From Data References", getName())
				.menuPath(MENU_RESIM, "Data", "To/From &References")
				.menuGroup(MENU_RESIM, "Data")
				.onAction(c -> firstFun())
				.buildAndInstall(tool);

			new ActionBuilder("Graph To Data References", getName())
					.menuPath(MENU_RESIM, "Data", "&To References")
					.menuGroup(MENU_RESIM, "Data")
					.onAction(c -> secondFun())
					.buildAndInstall(tool);
    	}
    	public void registerRefresh(RESimProvider provider) {
    		refreshProviders.add(provider);
    	}
    	public void setProgram(Program program) {
    		Msg.debug(this,  "setProgram");
    		this.program = program;
        }
    	private void loadOtherPlugins() {
    		// TBD, what does it take to get ghidra to load these?  it loads watchmarks...
            Msg.info(this,"loadOtherplugsin here goes");
            DebuggerREStackProvider dmp = (DebuggerREStackProvider) tool.getComponentProvider("REStack");
            if(dmp == null){
            	Msg.error(this,  "failed to get REStackProvider");
            	return;
            }
            try {
				dmp.refresh();
			} catch (Exception e) {
				Msg.error(this, getExceptString(e));
			}
            DebuggerWatchMarksProvider dwp = (DebuggerWatchMarksProvider) tool.getComponentProvider("WatchMarks");
            if(dwp == null){
                Msg.info(this, "watchmarks is potato");
                return;
            }
            try {
				dwp.refresh();
			} catch (Exception e) {
				Msg.error(this, getExceptString(e));
			}


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
    			if(provider != null) {
    				provider.coordinatesActivated(ev.getActiveCoordinates());
    			}else {
    				Msg.debug(this,  "Process event, no proder yet, "+ev.getToolEventName());
    			}
    		}
    	}
}
