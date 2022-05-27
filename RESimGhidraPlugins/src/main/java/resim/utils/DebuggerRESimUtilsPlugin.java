package resim.utils;

import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;
import agent.gdb.model.impl.GdbModelImpl;
import agent.gdb.pty.PtyFactory;
import docking.action.builder.ActionBuilder;

import java.lang.reflect.Field;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsPlugin;
import ghidra.app.plugin.core.debug.gui.objects.ObjectUpdateService;
import ghidra.app.services.DebuggerModelService;


import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.util.ShellUtils;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Trace;
import ghidra.util.database.UndoableTransaction;
import resim.restack.DebuggerREStackProvider;
import resim.watchmarks.DebuggerWatchMarksProvider;
import resim.bookmarks.DebuggerBookMarksProvider;

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
			TraceSelectionPluginEvent.class, //

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
    	private boolean didMapping = false;
 
        /**
         * Construct the RESimUtils plugin.
         * @param tool the pluginTool that this plugin is added to.
         */
        public DebuggerRESimUtilsPlugin(PluginTool tool){
                super(tool);
                this.tool = tool;
                this.program = null;
                this.impl = null;
                Msg.info(this,  "in resimutils plugin");
        		refreshProviders = new ArrayList<RESimProvider>();
                Msg.debug(this,  "did providers refresh");

        		
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


        public GdbManagerImpl getGdbManager() throws Exception {
        	GdbManagerImpl retval=null;
        	if(this.impl == null) {
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
	            this.impl = (GdbManagerImpl) f.get(model);
	            if(this.impl == null) {
	            	Msg.info(this, "Failed to get GdbManager");
	            }
        	}
        	retval = impl;
        	
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
        public void refreshClient() {
	        DebuggerObjectModel object_model;
			try {
				object_model = getObjectModel();
		        object_model.invalidateAllLocalCaches();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	        DebuggerObjectsProvider dbo;
			try {
				dbo = getDebuggerObjectsProvider();
		        dbo.refresh();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	        for(RESimProvider provider : refreshProviders) {
	        	provider.refresh();
	        }
        }
    	public Address addr(long addr) {
    		// Get an address in the program memory space.
            AddressSpace statRam = program.getAddressFactory().getDefaultAddressSpace();
            return statRam.getAddress(addr);
    	}

    	public String doRESimRefresh(String cmd){
    		String retval = doRESim(cmd);
    		if(retval != null) {
    			refreshClient();
    		}
    		return retval;
    	}
    	public String doRESim(String cmd) {
    		/**
    		 * Use the gdb monitor to send a command to RESim
    		 * @param cmd Command to execute
    		 * @return The response from RESim
    		 */
    		return doGdbCmd("monitor @cgc."+cmd);
    	}
    	public String doGdbCmd(String full_cmd) {
    		String retval = null;
            CompletableFuture<String> future = impl.consoleCapture(full_cmd, CompletesWithRunning.CANNOT);
            try {
            	retval = future.get();
    		} catch (InterruptedException e) {
    			// TODO Auto-generated catch block
    			e.printStackTrace();
    			Msg.error(this, "Failed resim command, interruptedException:"+full_cmd);
    		} catch (ExecutionException e) {
    			// TODO Auto-generated catch block
    			e.printStackTrace();
    			Msg.error(this,"Failed to resim command, execution exception:"+full_cmd);
    			Msg.error(this,  getExceptString(e));
    		}
            
            Msg.info(this,  "Done with doRESim");
            return retval;
    	}
    	protected Trace getCurrentTrace() {
            DebuggerTraceManagerService traces =
                    tool.getService(DebuggerTraceManagerService.class);

            Trace currentTrace = null;
            int failcount = 0;
            while(currentTrace == null){
                currentTrace = traces.getCurrentTrace();
                if(currentTrace == null){
                	Msg.debug(this,"no current trace, wait a sec");
                    try {
						Thread.sleep(1000);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
                    failcount++;
                    if(failcount > 10){
                        return null;
                    }
                }
            }
            return currentTrace;
    	}

        protected void doMapping(Long start, Long end) throws Exception{
            Msg.debug(this,"in doMapping\n");
            Long length = end - start;
            DebuggerStaticMappingService mappings =
                    tool.getService(DebuggerStaticMappingService.class);
            Trace currentTrace = getCurrentTrace();
            AddressSpace dynRam = currentTrace.getBaseAddressFactory().getDefaultAddressSpace();
            AddressSpace statRam = program.getAddressFactory().getDefaultAddressSpace();

            try (UndoableTransaction tid =
                    UndoableTransaction.start(currentTrace, "Add Mapping", true)) {
                    mappings.addMapping(
                            new DefaultTraceLocation(currentTrace, null, Range.atLeast(0L),
                                    dynRam.getAddress(start)),
                            new ProgramLocation(program, statRam.getAddress(start)),
                            length, false);
                    Msg.debug(this, "did mapping eh? tid is"+tid.toString());
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
            	Msg.error(this,"Error thrown by doMapping\n"+e.toString());
                e.printStackTrace();
            }
        }
        public void doMapping() {
            String cmd = "getSOMap()";
            String soJson = doRESim(cmd);
            if(soJson != null) {
            	parseSO(soJson);
            	didMapping = true;
            }else {
            	Msg.error(this,  "Failed to getSOMap");
            	
            }
        }
    	public CompletableFuture<? extends GdbModelImpl> build() {
    		// TBD Generalize, remove hardcoded paths.
    		String gdbCmd = "/home/mike/git/binutils-gdb/gdb/gdb -x /home/mike/git/ghidra/Ghidra/Debug/Debugger-agent-gdb/data/scripts/define_info32";
    		boolean existing = false;

    		List<String> gdbCmdLine = ShellUtils.parseArgs(gdbCmd);
    		GdbModelImpl model = new GdbModelImpl(PtyFactory.local());
    		return model
    				.startGDB(existing ? null : gdbCmdLine.get(0),
    					gdbCmdLine.subList(1, gdbCmdLine.size()).toArray(String[]::new))
    				.thenApply(__ -> model);
    	}
        public void attachDebug() {
        	/**
        	 * Create a gdb debugger and attach it to Simics
        	 *
        	 */
        	CompletableFuture<? extends GdbModelImpl> future = build();
			GdbModelImpl model = null;

        	try {
				model = future.get();
			} catch (InterruptedException e1) {
				// TODO Auto-generated catch block
				Msg.error(this,getExceptString(e1));
			} catch (ExecutionException e1) {
				// TODO Auto-generated catch block
				Msg.error(this, getExceptString(e1));
			}
            if (model == null) {
            	Msg.info(this, "Failed to get GdbManager, model is null");
                return;
            }
    		DebuggerModelService service = tool.getService(DebuggerModelService.class);
			service.addModel(model);

            Field f=null;
			try {
				f = GdbModelImpl.class.getDeclaredField("gdb");
	            f.setAccessible(true);

	            this.impl = (GdbManagerImpl) f.get(model);

			} catch (NoSuchFieldException e1) {
				// TODO Auto-generated catch block
				Msg.error(this, getExceptString(e1));
			} catch (SecurityException e1) {
				// TODO Auto-generated catch block
				Msg.error(this, getExceptString(e1));
			} catch (IllegalArgumentException e) {
				// TODO Auto-generated catch block
				Msg.error(this, getExceptString(e));
			} catch (IllegalAccessException e) {
				// TODO Auto-generated catch block
				Msg.error(this, getExceptString(e));
			}
            if(this.impl == null) {
            	Msg.info(this, "Failed to get GdbManager");
            	return;
            }

            //String remote = askString("Remote server?", "Enter host of remote server:");
            String cmd = "target remote mft-ref:9123";
            doGdbCmd(cmd);
            program = getProgram();
            if(program == null) {
            	Msg.error(this,  "Failed to get program");
            }else {
            	refreshOtherPlugins();

            }
        }
    	private void createActions() {
    		// we want to put all function pull-right menus in the same group
    		tool.setMenuGroup(new String[] { RESIM_MENU_PULLRIGHT }, RESIM_MENU_SUBGROUP,
    			RESIM_SUBGROUP_MIDDLE);
    		revToCursorAction = new RevToCursorAction("Rev to Cursor", this);
    		tool.addAction(revToCursorAction);
    		
    		tool.setMenuGroup(new String[] { MENU_RESIM, "RESim" }, "first");
        	new ActionBuilder("Attach Simulation", getName())
				.menuPath(MENU_RESIM, "Attach Simulation")
				.menuGroup(MENU_RESIM, "Attach")
				.onAction(c -> attachDebug())
				.buildAndInstall(tool);


    	}
        public static DebuggerRESimUtilsPlugin getRESimUtils(PluginTool tool) {
    	    DebuggerRESimUtilsPlugin resimUtils = null;
    	    List<Plugin> pluginList = tool.getManagedPlugins();
    	    for (Plugin p : pluginList) {
    	    	if(p.getClass() == DebuggerRESimUtilsPlugin.class) {
    	    		resimUtils = (DebuggerRESimUtilsPlugin) p;
    	    	}
    	    }

    	    if(resimUtils == null) {
    	    	Msg.out("No resimUtils, bail");
    	    }
    	    return resimUtils;
        }
    	public void registerRefresh(RESimProvider provider) {
    		refreshProviders.add(provider);
    	}

    	private void refreshOtherPlugins() {
    		/**
    		 * Load Refresh RESim plugins.
    		 */
            Msg.debug(this,"refresh plugins");
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
            DebuggerBookMarksProvider bmp = (DebuggerBookMarksProvider) tool.getComponentProvider("BookMarks");
            if(dwp == null){
                Msg.info(this, "watchmarks is potato");
                return;
            }
            try {
				bmp.refresh();
			} catch (Exception e) {
				Msg.error(this, getExceptString(e));
			}


    	}
        private Program getProgram() {

    		ProgramManager pm = tool.getService(ProgramManager.class);
    		if (pm != null) {
    			return pm.getCurrentProgram();
    		}
    		return null;
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
    				Msg.debug(this,  "Process event, no provider yet, "+ev.getToolEventName());
    			}
    		}else if(event instanceof TraceSelectionPluginEvent) {
    			Msg.debug(this,  "is traceSelection");
    			if(!didMapping && impl != null) {
    				// Do mapping as callback here, otherwise, mapping is attempted
    				// before ghidra debugger settles out.
    				doMapping();
    			}
    		}else {
    			Msg.debug(this,  "plugin event is "+event.getEventName());
    		}
    		
    	}
    	protected void locationChanged(ProgramLocation loc) {
    		Msg.debug(this,  "LOCATION CHANGED");
    	}
    	public boolean connected() {
    		if(impl != null) {
    			return true;
    		}else {
    			return false;
    		}
    	}
}
