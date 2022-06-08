package resim.utils;

import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;
import agent.gdb.model.impl.GdbModelImpl;
import agent.gdb.pty.PtyFactory;
import docking.ActionContext;
import docking.action.ToolBarData;
import docking.action.builder.ActionBuilder;

import java.lang.reflect.Field;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.ArrayList;
import java.util.List;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsPlugin;
import ghidra.app.plugin.core.debug.gui.objects.ObjectUpdateService;
import ghidra.app.services.DebuggerModelService;


import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.util.ShellUtils;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.services.TraceRecorder;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Trace;
import ghidra.util.database.UndoableTransaction;
import resim.utils.RESimResources.AbstractRefreshAction;
import resim.utils.RESimResources.AbstractRevStepAction;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.Thread;
import com.google.common.collect.Range;
@PluginInfo( //
        shortDescription = "RESim Utils", //
        description = "Manage connecting Ghidra to the Simics GDB server, manage the other RESim plugins and provide common functions.", //
        category = PluginCategoryNames.DEBUGGER, //
        packageName = DebuggerPluginPackage.NAME, //
        status = PluginStatus.STABLE, //
        eventsConsumed = {
            TraceActivatedPluginEvent.class, //
            TraceClosedPluginEvent.class, //
            TraceSelectionPluginEvent.class, //
            TraceRecorderAdvancedPluginEvent.class, //

        }, //
        servicesRequired = { //
        } // 
)
/*
Want this plugin to load first.  Does not otherwise need to extend Plugin, it has no window
*/
public class RESimUtilsPlugin extends Plugin {
        private PluginTool tool;
        private Program program;
        private GdbManagerImpl impl;
        GdbModelImpl model;

        public final static String RESIM_MENU_SUBGROUP = "RESim";
        public final static String RESIM_MENU_PULLRIGHT = "RESim";
        public final static String RESIM_SUBGROUP_MIDDLE = "M_Middle";
        public final static String RESIM_SUBGROUP_BEGINNING = "Begin";
        private ArrayList<RESimProvider> refreshProviders;
        private ArrayList<RESimProvider> initProviders;
        public final static String MENU_RESIM = "&RESim";
        protected RESimUtilsProvider provider;
        private boolean didMapping = false;
        private Trace currentTrace = null;
        protected RESimUtilsPlugin plugin = this;
 
        /**
         * Construct the RESimUtils plugin.
         * @param tool the pluginTool that this plugin is added to.
         */
        public RESimUtilsPlugin(PluginTool tool){
                super(tool);
                this.tool = tool;
                this.program = null;
                this.impl = null;
                Msg.debug(this,  "in resimutils plugin");
                refreshProviders = new ArrayList<RESimProvider>();
                initProviders = new ArrayList<RESimProvider>();
                
        }
        @Override
        protected void init() {
            Msg.info(this,  "in init");
            provider = new RESimUtilsProvider(this);

            createActions();


        }
        public static String getExceptString(Exception e) {
              StringWriter sw = new StringWriter();
              e.printStackTrace(new PrintWriter(sw));
              String stackTrace = sw.toString();
              return stackTrace;
        }


        /**
         * Get the instance of the GDBManagerImpl using tool.getService -- this is not currently used, see the build method.
         * @return The instance.
         */
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

        /**
         * Refresh the gdb client state values.
         * 
         */
        public void refreshClient(boolean from_resim) {
            if(from_resim) {
                DebuggerObjectModel object_model;
                DebuggerModelService model_service;
                try {
                    model_service = tool.getService(DebuggerModelService.class);
                    object_model = model_service.getCurrentModel();
                    object_model.invalidateAllLocalCaches();
                } catch (Exception e) {
                    Msg.error(this,  getExceptString(e));
                    return;
                }
                DebuggerObjectsProvider dbo;
                try {
                    dbo = getDebuggerObjectsProvider();
                    //DebuggerTraceManagerService traceManager =
                    //        tool.getService(DebuggerTraceManagerService.class);
                    //DebuggerCoordinates current = traceManager.getCurrent();
                    //TargetObject target = model_service.getTarget(current.getTrace());
                    //wtf.fetchElements(true);
                    //dbo.refresh(wtf);
                    //refreshTraces();
                    dbo.refresh("Threads");
                    dbo.getTraceManager().getCurrent();
                    Msg.debug(this, "refreshClient did refresh of debugger");
                } catch (Exception e) {
                    Msg.error(this,  getExceptString(e));
                }
                //Msg.debug(this,  "refreshClient do ghidra regs");
                //ghidraRegs();
                //refreshRegisters();
            }
            for(RESimProvider provider : refreshProviders) {
                Msg.debug(this, "refreshClient refresh a provider"); 
                provider.refresh();
            }
            if(from_resim) {
                Swing.runIfSwingOrRunLater(
                    () -> refreshRegisters());       
            }
        }
        public Address addr(long addr) {
            /**
             * Get an address in the program memory space.
             * @param addr The integer address.
             * @return Ghidra address
             */
            AddressSpace statRam = program.getAddressFactory().getDefaultAddressSpace();
            return statRam.getAddress(addr);
        }
        public void addMessage(String msg) {
            provider.addMessage("RESim:", msg);
        }
        public CompletableFuture<String> doRESimRefresh(String cmd){
            /**
             * Use the gdb monitor to send a command to RESim and refresh the client when done.
             * @param cmd Command to execute
             * @return The response from RESim
             */
            Msg.debug(this,"doRESimRefresh do cmd: "+cmd);
            CompletableFuture<String> retval = doRESim(cmd).thenApply(result ->{
                if(result != null){
                    Msg.debug(this, "doRESimRefresh did command, refresh client.");
                    addMessage(result);
                    refreshClient(true);
                }
                return result;
            });
            return retval;
        }
        public CompletableFuture<String> doRESim(String cmd) {
            /**
             * Use the gdb monitor to send a command to RESim
             * @param cmd Command to execute
             * @return The response from RESim
             */
            return doGdbCmd("monitor @cgc."+cmd);
        }
        public CompletableFuture<String> doGdbCmd(String full_cmd) {
            /**
             * Send a command to the GDB console.
             * @param cmd Command to execute
             * @return The response from GDB
             */
            return impl.consoleCapture(full_cmd, CompletesWithRunning.CANNOT);
        }
        /**
         * Get the current Ghidra debugger trace, may sleep up to 10 seconds if no trace is found.
         * @return The Trace.
         */
        public Trace getCurrentTrace() {
            DebuggerTraceManagerService traces =
                    tool.getService(DebuggerTraceManagerService.class);

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

        /**
         * Map the dynamic and static listings so that their displays sync.
         * @param start The starting address
         * @param end The ending address
         */
        protected void addMapping(Long start, Long end) throws Exception{
            Msg.debug(this,"in addMapping\n");
            Long length = end - start;
            DebuggerStaticMappingService mappings =
                    tool.getService(DebuggerStaticMappingService.class);
            getCurrentTrace();
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
        /**
         * Parse a given json string generated by RESim's getSOMap command and use #addMapping to 
         * to map those static and dynamic listing addresses.
         * @param all_string The json string from RESim
         */
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
                addMapping(start, end);
                Msg.debug(this,"did call addMapping");
            }catch(java.lang.Exception e){
                Msg.error(this,"Error thrown by addMapping\n"+e.toString());
                e.printStackTrace();
            }
        }
        public void doMapping() {
            /**
             * Get program information from RESim and use it to map static/dynamic listings.
             *
             */
            String cmd = "getSOMap()";
            doRESim(cmd).thenApply(so_json ->{
                if(so_json != null) {
                    parseSO(so_json);
                    didMapping = true;
                }else {
                    Msg.error(this,  "Failed to getSOMap");
                }
                return so_json;
            });
        }
        public CompletableFuture<? extends GdbModelImpl> build() {
            /**
             * Create a GdbModelImpl and provide it with a gdb command line.
             *
             */
            // TBD Generalize, remove hardcoded paths.
            String gdbCmd = "/home/mike/git/binutils-gdb/gdb/gdb -x /home/mike/git/ghidra/Ghidra/Debug/Debugger-agent-gdb/data/scripts/define_info32";
            boolean existing = false;

            List<String> gdbCmdLine = ShellUtils.parseArgs(gdbCmd);
            model = new GdbModelImpl(PtyFactory.local());
            return model
                    .startGDB(existing ? null : gdbCmdLine.get(0),
                        gdbCmdLine.subList(1, gdbCmdLine.size()).toArray(String[]::new))
                    .thenApply(__ -> model);
        }
        public void attachDebug() {
            CompletableFuture <? extends GdbManagerImpl>gdb_manager = createDebug();
            gdb_manager.thenApply(manager -> {
               this.impl = manager;
               CompletableFuture<String> target = attachTarget();
               return manager;
            });
        }
        public CompletableFuture<? extends GdbManagerImpl> createDebug() {
            /**
             * Create a gdb debugger and attach it to Simics
             *
             */
            CompletableFuture<? extends GdbModelImpl> future = build();
            return future.thenApply(model ->{
                GdbManagerImpl new_impl = null;
                Msg.debug(this,  "createDebug, thenApply");
                DebuggerModelService service = tool.getService(DebuggerModelService.class);
                service.addModel(model);

                Field f=null;
                try {
                    f = GdbModelImpl.class.getDeclaredField("gdb");
                } catch (NoSuchFieldException | SecurityException e) {
                    Msg.error(this, getExceptString(e));
                    return null;
                }
                f.setAccessible(true);
                try {
                    new_impl = (GdbManagerImpl) f.get(model);
                } catch (IllegalArgumentException | IllegalAccessException e) {
                    Msg.error(this, getExceptString(e));
                    return null;
                }
                Msg.debug(this,  "createDebug done?");
                this.impl = new_impl;
                return new_impl;
            });    
        }
        public void doRest() {
            program = getProgram();
            if(program == null) {
                Msg.error(this,  "Failed to get program");
            }else {
                initOtherPlugins();
                for(RESimProvider provider : refreshProviders) {
                    provider.refresh();
                }
                Msg.debug(this,"Finished initializing the registered plugins.");
            }         
        }
        public CompletableFuture<String> attachTarget() {
            Msg.debug(this,  "attachTarget");;


            //Msg.error(this, getExceptString(e));

            if(this.impl == null) {
                Msg.error(this, "Failed to get GdbManager");
            }
            //String remote = askString("Remote server?", "Enter host of remote server:");
            String cmd = "target remote mft-ref:9123";
            

            CompletableFuture<String> target_results = impl.consoleCapture(cmd, CompletesWithRunning.CANNOT);
            Msg.debug(this, "attachDebug, no do thenApply?");
            /*
            try {
                target_results.get();
            } catch (InterruptedException | ExecutionException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            */
            CompletableFuture<String> result = target_results.thenApply(s -> {
                Msg.debug(this, "in thenapply...");
                provider.initConsole();
                return s;
            });
             
            Msg.debug(this,  "back from thenapply");
            
            //doGdbCmd(cmd);

            return target_results;
        }

        private void createActions() {
            // we want to put all function pull-right menus in the same group
            tool.setMenuGroup(new String[] { RESIM_MENU_PULLRIGHT }, RESIM_MENU_SUBGROUP,
                RESIM_SUBGROUP_MIDDLE);
            RevToCursorAction revToCursorAction = new RevToCursorAction("Rev to cursor", "revToAddr", this, null);
            tool.addAction(revToCursorAction);
            
            tool.setMenuGroup(new String[] { MENU_RESIM, "RESim" }, "first");
            new ActionBuilder("Attach Simulation", getName())
                .menuPath(MENU_RESIM, "Attach Simulation")
                .menuGroup(MENU_RESIM, "Attach")
                .onAction(c -> attachDebug())
                .buildAndInstall(tool);
            new ActionBuilder("Reverse step into", getName())
                .menuPath(RESimUtilsPlugin.MENU_RESIM, "Reverse", "&Step-into")
                .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Reverse")
                .onAction(c -> revStep(true))
                .buildAndInstall(tool);
            new ActionBuilder("Reverse step over", getName())
                .menuPath(RESimUtilsPlugin.MENU_RESIM, "Reverse", "&Step-over")
                .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Reverse")
                .onAction(c -> revStep(false))
                .buildAndInstall(tool);

        }
        public static RESimUtilsPlugin getRESimUtils(PluginTool tool) {
            /**
             * @return The RESim utils plugin.
             *
             */
            Msg.out("getRESimUtilsPlugin");
            RESimUtilsPlugin resimUtils = null;
            List<Plugin> pluginList = tool.getManagedPlugins();
            for (Plugin p : pluginList) {
                if(p.getClass() == RESimUtilsPlugin.class) {
                    resimUtils = (RESimUtilsPlugin) p;
                    break;
                }
            }

            if(resimUtils == null) {
                Msg.out("No resimUtils, bail");
            }
            return resimUtils;
        }
        public void registerRefresh(RESimProvider provider) {
            /**
             * Register a RESim plugin to be refreshed each time program state changes.
             */
            if(impl == null){
                Msg.debug(this,"register plugin for refresh");
                refreshProviders.add(provider);
            }else{
                Msg.debug(this,"registerRefresh Already connected, just refresh the plugin.");
                provider.refresh();
            }
        }
        public void registerInit(RESimProvider provider) {
            /**
             * Register a RESim plugin to be initialized when the debugger is attached.
             */
            if(impl == null){
                Msg.debug(this,"register plugin for init ");
                initProviders.add(provider);
            }else{
                Msg.debug(this,"registerInit Already connected, just refresh the plugin.");
                provider.refresh();
            }
        }

        private void initOtherPlugins() {
            /**
             * Refresh plugins registered using registerInit
             */
            Msg.debug(this,"init plugins");
            for(RESimProvider provider : initProviders) {
                provider.refresh();
            }



        }
        private Program getProgram() {
            ProgramManager pm = null;
            int failcount = 0;
            while(pm == null){
                pm = tool.getService(ProgramManager.class);
                if(pm == null){
                    Msg.debug(this,"no Program manager, wait a sec");
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        // TODO Auto-generated catch block
                        Msg.error(this,  getExceptString(e));
                    }
                    failcount++;
                    if(failcount > 10){
                        return null;
                    }
                }
            }
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
                Msg.debug(this,  "is TraceActivatedPluginEvent");
                if(connected()) {
                    refreshClient(false);
                }
            }else if(event instanceof TraceSelectionPluginEvent) {
                Msg.debug(this,  "is traceSelection");
                if(!didMapping && impl != null) {
                    // Do mapping as callback here, otherwise, mapping is attempted
                    // before ghidra debugger settles out.
                    doRest();
                    doMapping();
                }
            }else if(event instanceof TraceRecorderAdvancedPluginEvent) {
                Msg.debug(this,  "is trace advanced event");
               // refreshRegisters();

            }else {
                Msg.debug(this,  "plugin event is "+event.getEventName());
            }
            
        }
        public void refreshTraces() {
            //Thanks to nsadeveloper789!
            // There is no need to fish this from the ObjectUpdateService, you can get it directly
            Msg.debug(this, "refreshTraces");
            DebuggerModelService modelService = tool.getService(DebuggerModelService.class);
            // The current model is retrieved with one method, no need to stream or filter
            DebuggerObjectModel model = modelService.getCurrentModel();
            DebuggerTraceManagerService traceManager =
                    tool.getService(DebuggerTraceManagerService.class);
            // There are also getCurreentTrace(), etc., if you want just the one thing
            DebuggerCoordinates current = traceManager.getCurrent();
            Msg.debug(this, "refreshTraces got current");

            // Now, we need to get the relevant recorder
            TraceRecorder recorder = modelService.getRecorder(current.getTrace());
            if(recorder == null) {
                Msg.debug(this,  "No recorder yet, skip refreshRegisters");
                return;
            }
            recorder.getTarget().invalidateCaches();
            recorder.getTarget().fetchElements(true);

            Msg.debug(this, "refreshTraces all done");
        }
        public void refreshRegisters() {
            //Thanks to nsadeveloper789!
            // There is no need to fish this from the ObjectUpdateService, you can get it directly
            Msg.debug(this, "refreshRegisters");
            DebuggerModelService modelService = tool.getService(DebuggerModelService.class);
            // The current model is retrieved with one method, no need to stream or filter
            DebuggerObjectModel model = modelService.getCurrentModel();
            DebuggerTraceManagerService traceManager =
                    tool.getService(DebuggerTraceManagerService.class);
            // There are also getCurreentTrace(), etc., if you want just the one thing
            DebuggerCoordinates current = traceManager.getCurrent();
            Msg.debug(this, "refreshRegisters got current");

            // Now, we need to get the relevant recorder
            TraceRecorder recorder = modelService.getRecorder(current.getTrace());
            if(recorder == null) {
                Msg.debug(this,  "No recorder yet, skip refreshRegisters");
                return;
            }
            // There's a chance of an NPE here if there is no "current frame"
            TargetRegisterBank bank =
                recorder.getTargetRegisterBank(current.getThread(), current.getFrame());
            Msg.debug(this, "refreshRegisters got thread");
           
            // Now do the same to the bank as before
            try {
                Msg.debug(this, "refreshRegistrs invalidate caches");
                bank.invalidateCaches().get();
                Msg.debug(this, "refreshRegistrs fetch elements");
                bank.fetchElements(true).get();
                Msg.debug(this, "refreshRegistrs done");

            } catch (InterruptedException | ExecutionException e) {
                Msg.error(this,  getExceptString(e));
            }
            Msg.debug(this, "refreshRegisters all done");
        }
        public boolean connected() {
           if(impl != null) {
               return true;
            }else {
               return false;
            }
        }
        protected class RevStepAction extends AbstractRevStepAction {
            public static final String GROUP = DebuggerResources.GROUP_CONTROL;

            public RevStepAction() {
                super(plugin);
                setToolBarData(new ToolBarData(ICON, GROUP, "4"));
                provider.addLocalAction(this);
                setEnabled(false);
            }

            @Override
            public void actionPerformed(ActionContext context) {
                revStep(true);
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {

                return true;
            }
        }
        protected void revStep(boolean step_into) {
            String cmd = null;
            Msg.debug(this,  "revStep");
            if(step_into){
                cmd = "reverseToCallInstruction(True)";
            }else{
                cmd = "reverseToCallInstruction(False)";
            }
            doRESimRefresh(cmd);
        }
 
        
}
