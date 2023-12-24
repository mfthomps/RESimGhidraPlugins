package resim.utils;

import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;
import agent.gdb.model.impl.GdbModelImpl;
import ghidra.pty.linux.LinuxPtyFactory;
import ghidra.pty.PtyFactory;
import docking.DockingUtils;
import docking.action.KeyBindingData;
import docking.action.builder.ActionBuilder;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import javax.swing.KeyStroke;
import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import org.apache.commons.io.FilenameUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsPlugin;
import ghidra.app.plugin.core.debug.gui.objects.ObjectUpdateService;
import ghidra.app.services.DebuggerModelService;
import ghidra.app.plugin.core.colorizer.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;

import ghidra.dbg.util.ShellUtils;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.debug.api.model.TraceRecorder;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceModuleManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
//import ghidra.util.database.UndoableTransaction;
import ghidra.app.plugin.core.debug.service.model.RecorderPermanentTransaction;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import java.awt.Color;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.Thread;
import com.google.common.collect.Range;
@PluginInfo( //
        shortDescription = "RESim Utils", //
        description = "Manage connecting Ghidra to the Simics GDB server, manage the other RESim plugins and provide common functions.", //
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
        public final static String RESIM_HOST_PORT = "RESIM_HOST_PORT";
        public final static String RESIM_TARGET_ARCH = "RESIM_TARGET_ARCH";
        public final static String RESIM_GDB_PATH = "RESIM_GDB_PATH";
        public final static String RESIM_FSROOT_PATH = "RESIM_FSROOT_PATH";

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
/*
        private DebuggerObjectsProvider getDebuggerObjectsProvider() throws Exception {
            DebuggerObjectsProvider dop = (DebuggerObjectsProvider) tool.getComponentProvider("Objects");
            if(dop == null) {
                Msg.debug(this,  "dop is none");
                DebuggerObjectsPlugin objects =
                    (DebuggerObjectsPlugin) tool.getService(ObjectUpdateService.class);
                return objects.getProvider(0);
            }else {
                return dop;
            }
        }
*/
        /**
         * Refresh the gdb client state values.
         * 
         */
        public void refreshClient(boolean from_resim) {
            Msg.debug(this, "refreshClient from_resim? "+from_resim);
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
                    //dbo = getDebuggerObjectsProvider();
                    dbo = (DebuggerObjectsProvider) tool.getComponentProvider("Objects");
                    dbo.refresh("Threads");
                    dbo.getTraceManager().getCurrent();
                    Msg.debug(this, "refreshClient did refresh of debugger");
                } catch (Exception e) {
                    Msg.error(this,  getExceptString(e));
                }
                DebuggerTraceManagerService dts = tool.getService(DebuggerTraceManagerService.class);
                dts.getCurrent();
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
        public Address addrDyn(long addr) {
            AddressSpace dynRam = currentTrace.getBaseAddressFactory().getDefaultAddressSpace();
            return dynRam.getAddress(addr);
            
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
            CompletableFuture <String> cmdfuture = doRESim(cmd);
            String result = null;
            try {
                result = cmdfuture.get();
            } catch (InterruptedException | ExecutionException e) {
                // TODO Auto-generated catch block
                Msg.error(this,  getExceptString(e));
                return null;
            }
            Msg.debug(this,  "back from cmd get, got "+result);
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            return doRESim("getEIPWhenStopped()").thenApply(waitresult -> {
                Msg.debug(this,  "back from geteip with "+waitresult);
                if(waitresult != null){

                        Msg.debug(this, "doRESimRefresh did command, refresh client.");
                        addMessage(waitresult);
                        refreshClient(true);
                }
                return waitresult;
            });
        }
        public CompletableFuture<String> doRESim(String cmd) {
            /**
             * Use the gdb monitor to send a command to RESim
             * @param cmd Command to execute
             * @return The response from RESim
             */
            return doGdbCmd("monitor @cgc."+cmd).thenApply(result -> {
                String NONE = "\nNone";
                result = result.trim();
                if(result.endsWith(NONE)) {
                    Msg.debug(this, "removing None"); 
                    result = result.substring(0,(result.length()-NONE.length()));
                    
                }
                return result;
            });
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
         * Parse a given json string generated by RESim's getSOMap command and use #addModules to add 
         * those to the Ghidra modules plugin.
         * @param all_string The json string from RESim
         */
        protected void parseSO(String all_string){
            Msg.debug(this,"in parseSO\n");
            // TBD initialize trace from more logical location?
            getCurrentTrace();
            Object obj = Json.getJson(all_string);
            if(obj == null){
                Msg.debug(this,"Error getting json of somap");
                return;
            }
            java.util.HashMap<Object, Object> somap = (java.util.HashMap<Object, Object>) obj;

            Msg.debug(this,"did hash parseSO\n");
            Msg.debug(this,"size of hashmap is "+ somap.size());
            addModule(somap);    
            
        }
        protected void addModule(java.util.HashMap<Object, Object> somap){
            /**
             * Add a module and its sections, as defined by a RESim SO map json, to the Ghidra modules
             * @param somap The json hashmap
             */
            Long pid_o = (Long) somap.get("group_leader");
            Msg.debug(this,"in parseSO pid_o is "+pid_o);
            Long start = (Long) somap.get("prog_start");
            Long end = (Long) somap.get("prog_end");
            String path = (String) somap.get("prog");
            String name = (String) FilenameUtils.getBaseName(path);
            Msg.debug(this,  "get addr");
            AddressRangeImpl ar = new AddressRangeImpl(this.addrDyn(start), this.addrDyn(end));
            TraceModule newmod = null;
            // TBD what should the range be?  Most recent snap?"
            Range <Long> r = Range.closed(0L, 9999999L);
            TraceModuleManager tm = currentTrace.getModuleManager();
            try (RecorderPermanentTransaction tid =
                    RecorderPermanentTransaction.start(currentTrace, "Add Module")) {
                
                try {
                    newmod = tm.addModule(path, name, ar, Lifespan.nowOn(0));
                    //Msg.debug(this,  "back from addModulePath");
                } catch (DuplicateNameException e1) {
                    Msg.debug(this, getExceptString(e1));
                }
            }

            //Msg.debug(this, "bout to do sections?");
            ArrayList <java.util.HashMap<Object, Object>> sections=null;
            try {
                sections = (ArrayList <java.util.HashMap<Object, Object>>) somap.get("sections");
            }catch (Exception e) {
                Msg.debug(this, getExceptString(e));
            }
            Msg.debug(this,  "parseSO, num sections is "+sections.size());
            for(Object o : sections) {
                java.util.HashMap<Object, Object> section = (java.util.HashMap<Object, Object>) o;
                start = (Long) section.get("locate");
                end = (Long) section.get("end");
                ar = new AddressRangeImpl(this.addrDyn(start), this.addrDyn(end));
                path = (String) section.get("file");
                name = FilenameUtils.getBaseName(path);
                //Msg.debug(this, "parseSO add section");
                try (RecorderPermanentTransaction tid =
                        RecorderPermanentTransaction.start(currentTrace, "Add Section")) {
                    
                    try {
                        newmod.addSection(path, name, ar);
                    } catch (DuplicateNameException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                    //Msg.debug(this, "parseSO back from add section");
                }
            }
        }

        public void doMapping() {
            /**
             * Get program information from RESim and use it to map static/dynamic listings.
             *
             */
            Msg.debug(this,  "in doMapping");
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
        public void doThreads() {
            /**
             * Get thread information from RESim and add it to ghidra's threads.
             *
             */
            Msg.debug(this,  "in doThreads");
            String cmd = "getThreads()";
            doRESim(cmd).thenApply(thread_json ->{
                if(thread_json != null) {
                    parseThreads(thread_json);
                }else {
                    Msg.error(this,  "Failed to getThreads");
                }
                return thread_json;
            });
        }
        protected void parseThreads(String all_string){
            Msg.debug(this,"in parseThreads json:");
            Msg.debug(this,  all_string);
            // TBD initialize trace from more logical location?
            getCurrentTrace();
            Object obj = Json.getJson(all_string);
            if(obj == null){
                Msg.debug(this,"parseThreads, Error getting json of threads");
                return;
            }
            ArrayList <java.util.HashMap<Object, Object>> threads=null;
            try {
                threads = (ArrayList <java.util.HashMap<Object, Object>>) obj;
            }catch (Exception e) {
                Msg.debug(this, getExceptString(e));
            }
            try (RecorderPermanentTransaction tid =
                    RecorderPermanentTransaction.start(currentTrace, "Get Thread")) {
                    TraceThreadManager manager = currentTrace.getThreadManager();
                    Collection<? extends TraceThread> all_threads = manager.getAllThreads();
                    for(TraceThread t : all_threads) {
                        Msg.debug(this,  "thread name "+t.getName()+" path "+t.getPath());
                    }
            }
            for(java.util.HashMap<Object, Object> t : threads){
                addThread(t);
            }
             
        }
        String writeGDBMappingMacro() {
            String retval = null;
            String tmpdir = System.getProperty("java.io.tmpdir");
            System.out.println("Temp file path: " + tmpdir);
            List<String> content = Arrays.asList("define info proc mappings",
                    "echo 0x0 0x0 0xbfffffff 0x0 lomem \\n",
                    "echo 0xc0000000 0xfffffff 0x800000 0x0 himem",
                    "end");
                   
            try {

                // Create an temporary file
                Path temp = Files.createTempFile("32bit", ".mapping");
                System.out.println("Temp file : " + temp);
                
                Files.write(temp,  content, StandardOpenOption.CREATE);
                retval = temp.toString();

            } catch (IOException e) {
                e.printStackTrace();
            }
            return retval;
        }
        public CompletableFuture<? extends GdbModelImpl> build() {
            /**
             * Create a GdbModelImpl and provide it with a gdb command line.
             *
             */
            // TBD Generalize, remove hardcoded paths.
            String gdbpath = Preferences.getProperty(RESIM_GDB_PATH);
            if(gdbpath == null) {
                Msg.error(this,  "Missing gdb path configuration value");
                JOptionPane.showMessageDialog(plugin.getTool().getActiveWindow(), "Missing gdb path, use RESim / Configure menu.",
                        "Missing gdb path", JOptionPane.ERROR_MESSAGE);
                return null;
            }
            File target_file = new File(gdbpath);
            if(!target_file.exists()) {
                Msg.error(this,  "No program found at "+gdbpath);
                JOptionPane.showMessageDialog(plugin.getTool().getActiveWindow(), "Missing gdb executalbe. No file found at:"+gdbpath,
                        "Missing gdb executable", JOptionPane.ERROR_MESSAGE);
                return null;
            }
            String fsrootpath = Preferences.getProperty(RESIM_GDB_PATH);
            if(fsrootpath == null) {
                Msg.error(this,  "Missing file system root path configuration value");
                JOptionPane.showMessageDialog(plugin.getTool().getActiveWindow(), "Missing fs root path, use RESim / Configure menu.",
                        "Missing fs root path", JOptionPane.ERROR_MESSAGE);
                return null;
            }
            target_file = new File(fsrootpath);
            if(!target_file.exists()) {
                Msg.error(this,  "No program found at "+fsrootpath);
                JOptionPane.showMessageDialog(plugin.getTool().getActiveWindow(), "Missing fs root. No directory found at:"+fsrootpath,
                        "Missing fs root directory.", JOptionPane.ERROR_MESSAGE);
                return null;
            }

            Program p = getProgram();
            String path = p.getExecutablePath();
            Msg.debug(this,  "from getProgram, got "+path);
            String target = Preferences.getProperty(RESIM_TARGET_ARCH);
            Msg.debug(this,  "build, target is "+target);
            String mapinfo = writeGDBMappingMacro();

            String arch_info = "";
            if(target != null){
                if(! target.equals("auto")){
                    arch_info = " -ex \"set architecture "+target+ "\" ";
                }
            }
            String gdb_cmd = gdbpath+" -x "+mapinfo+arch_info+" -ex \"set sysroot "+fsrootpath+"\" -x "+mapinfo+" "+path;
            Msg.debug(this,  "gdb cmd is "+gdb_cmd);
                 
            boolean existing = false;
            List<String> gdbCmdLine = ShellUtils.parseArgs(gdb_cmd);
            //model = new GdbModelImpl(new LinuxPtyFactory());
            model = new GdbModelImpl(PtyFactory.local());
            return model
                    .startGDB(existing ? null : gdbCmdLine.get(0),
                        gdbCmdLine.subList(1, gdbCmdLine.size()).toArray(String[]::new))
                    .thenApply(__ -> model);
        }
        public void attachDebugxx() {
            CompletableFuture <? extends GdbManagerImpl>gdb_manager = createDebug();
            gdb_manager.thenApply(manager -> {
               this.impl = manager;
               CompletableFuture<String> target = attachTarget();
               return target;
            });
        }
        public void attachDebug() {
            CompletableFuture <? extends GdbManagerImpl>gdb_manager = createDebug();
            gdb_manager.thenApply(manager -> {

                   CompletableFuture<String> attach_result = attachTarget();
                   return attach_result.thenApply(y -> {
                       Msg.debug(this,  "no defined arch, do attach");
                       return y;
                   });                                 

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
                /*
                This is already done by the event handler during init.
                for(RESimProvider provider : refreshProviders) {
                    provider.refresh();
                }
                */
                Msg.debug(this,"Finished initializing the registered plugins.");
            }         
        }
        public void setHostPort() {
            String orig_host_port = Preferences.getProperty(RESIM_HOST_PORT);
            String host_port = JOptionPane.showInputDialog(null, "Enter host:port", orig_host_port);
            if(host_port == null){
                host_port = orig_host_port;
            } 
            Preferences.setProperty(RESIM_HOST_PORT, host_port);
        }
        public void setGdbPath() {
            String gdbpath = Preferences.getProperty(RESIM_GDB_PATH);
            JFileChooser fc = new JFileChooser(gdbpath);
            int got = fc.showOpenDialog(tool.getActiveWindow());
            if(got == JFileChooser.APPROVE_OPTION) {
                File selected = fc.getSelectedFile();
                Preferences.setProperty(RESIM_GDB_PATH, selected.toString());
            }
        }
        public void setFSRootPath() {
            String fsroot = Preferences.getProperty(RESIM_FSROOT_PATH);
            JFileChooser fc = new JFileChooser(fsroot);
            fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int got = fc.showOpenDialog(tool.getActiveWindow());
            if(got == JFileChooser.APPROVE_OPTION) {
                File selected = fc.getSelectedFile();
                Preferences.setProperty(RESIM_FSROOT_PATH, selected.toString());
            }
        }
        public void setTargetArch() {
            String target = Preferences.getProperty(RESIM_TARGET_ARCH);
            if(target == null) {
                target = "auto";
            }

            Object[] choices = {"auto", "armv7"};
            String s = (String)JOptionPane.showInputDialog(
                    null,
                    "Select target architecture:",
                    "Target Selection",
                    JOptionPane.PLAIN_MESSAGE,
                    null,
                    choices,
                    target);
            if(s != null) {
                Preferences.setProperty(RESIM_TARGET_ARCH, s);
                Msg.debug(this,  "target arch set to "+s);
            }
            
        }
        public CompletableFuture<String> setArch(){
            /**
             * NOT USED, seems to be a race condition?
             */
            String cmd = "show architecture";
            CompletableFuture<String> show_results = impl.consoleCapture(cmd, CompletesWithRunning.CANNOT);
            show_results.thenApply(x -> {
                String show_arch = null;
                try {
                    show_arch = show_results.get();
                } catch (InterruptedException | ExecutionException e1) {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }
                Msg.debug(this,  "show arch results "+show_arch);
                if(show_arch.contains("arm")) {
                    Msg.debug(this, "setArch sees arm, make armv7");
                    String set_cmd = "set architecture armv7";
                    CompletableFuture<String> target_results = impl.consoleCapture(set_cmd, CompletesWithRunning.CANNOT);
                    return target_results.thenApply(y -> {
                        Msg.debug(this,  "setArch did set architecture "+target_results);
                        return y;
                    });                  
                }else {
                    return show_results;
                }
            });

            return show_results;
        }
        public CompletableFuture<String> attachTarget() {
            Msg.debug(this,  "attachTarget");;
            if(this.impl == null) {
                Msg.error(this, "Failed to get GdbManager");
            }
            String host_port = Preferences.getProperty(RESIM_HOST_PORT);

            if(host_port == null){
                Msg.error(this,  "Host:port is null?");
                return null;
            }  
            String cmd = "target remote "+ host_port;
            

            CompletableFuture<String> target_results = impl.consoleCapture(cmd, CompletesWithRunning.CANNOT);
            Msg.debug(this, "attachDebug, no do thenApply?");

            CompletableFuture<String> result = target_results.thenApply(s -> {
                Msg.debug(this, "in thenapply...");
                provider.initConsole();
                return s;
            });
             
            Msg.debug(this,  "back from thenapply");
            return target_results;
        }

        private void createActions() {
            /* Cursor and register actions for right-click menu popups.  Also see actions
             * defined in bookmarks, e.g., revTaint functions that generate bookmarks.
             */
            tool.setMenuGroup(new String[] { RESIM_MENU_PULLRIGHT }, RESIM_MENU_SUBGROUP,
                RESIM_SUBGROUP_MIDDLE);
            RESimCursorAction revToCursorAction = new RESimCursorAction("Rev to cursor", "revToAddr", this, null, true);
            revToCursorAction.setKeyBindingData(new KeyBindingData(
                KeyStroke.getKeyStroke(KeyEvent.VK_F4, InputEvent.SHIFT_DOWN_MASK)));
            tool.addAction(revToCursorAction);

            RESimCursorAction runToCursorAction = new RESimCursorAction("Run to cursor", "doBreak", this, null, true);
            runToCursorAction.setKeyBindingData(new KeyBindingData(
                KeyStroke.getKeyStroke(KeyEvent.VK_F4, DockingUtils.CONTROL_KEY_MODIFIER_MASK)));
            tool.addAction(runToCursorAction);
            
            RESimRegAction revModRegAction = new RESimRegAction("Rev mod register", "revToModReg", this, null);
            tool.addAction(revModRegAction);
            RESimCursorAction revModAddrAction = new RESimCursorAction("Rev mod address", "revToWrite", this, null);
            tool.addAction(revModAddrAction);

            tool.setMenuGroup(new String[] { MENU_RESIM, "RESim" }, "first");

            RESimListingGoToAction lc = new RESimListingGoToAction("Goto address", this);
            tool.addAction(lc);
            /*
            new ActionBuilder("Manual map", getName())
                .menuPath(MENU_RESIM, "Manual map")
                .menuGroup(MENU_RESIM, "map")
                .onAction(c -> manualMap())
                .buildAndInstall(tool);
                */
            /*
             * Main menu RESim entries
             */
            new ActionBuilder("Attach Simulation", getName())
                .menuPath(MENU_RESIM, "Attach Simulation")
                .menuGroup(MENU_RESIM, "Attach")
                .onAction(c -> attachDebug())
                .keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_R, InputEvent.SHIFT_DOWN_MASK))
                .buildAndInstall(tool);
            new ActionBuilder("Reverse step into", getName())
                .menuPath(RESimUtilsPlugin.MENU_RESIM, "Reverse", "&Step-into")
                .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Reverse")
                .onAction(c -> doRESimRefresh("revStepInto()"))
                .keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_F8, InputEvent.CTRL_DOWN_MASK))
                .buildAndInstall(tool);
            new ActionBuilder("Reverse step over", getName())
                .menuPath(RESimUtilsPlugin.MENU_RESIM, "Reverse", "&Step-over")
                .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Reverse")
                .onAction(c -> doRESimRefresh("revStepOver()"))
                .keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_F10, InputEvent.CTRL_DOWN_MASK))
                .buildAndInstall(tool);
            new ActionBuilder("Reverse to text", getName())
                .menuPath(RESimUtilsPlugin.MENU_RESIM, "Reverse", "&to text")
                .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Reverse")
                .onAction(c -> doRESimRefresh("revToText()"))
                .buildAndInstall(tool);
            new ActionBuilder("Define host:port", getName())
                .menuPath(RESimUtilsPlugin.MENU_RESIM, "Configure", "&Define host:port")
                .menuGroup(RESimUtilsPlugin.MENU_RESIM, "host:port")
                .onAction(c -> setHostPort())
                .buildAndInstall(tool);
            new ActionBuilder("Define gdb path", getName())
                .menuPath(RESimUtilsPlugin.MENU_RESIM, "Configure", "&Define gdb path")
                .menuGroup(RESimUtilsPlugin.MENU_RESIM, "gdb path")
                .onAction(c -> setGdbPath())
                .buildAndInstall(tool);
            new ActionBuilder("Define FS root", getName())
                .menuPath(RESimUtilsPlugin.MENU_RESIM, "Configure", "&Define file system root")
                .menuGroup(RESimUtilsPlugin.MENU_RESIM, "FS Root")
                .onAction(c -> setFSRootPath())
                .buildAndInstall(tool);
            new ActionBuilder("Set target arch", getName())
                .menuPath(RESimUtilsPlugin.MENU_RESIM, "Configure", "&Set target arch")
                .menuGroup(RESimUtilsPlugin.MENU_RESIM, "target")
                .onAction(c -> setTargetArch())
                .buildAndInstall(tool);
            new ActionBuilder("Color blocks", getName())
            .menuPath(MENU_RESIM, "Color blocks")
            .menuGroup(MENU_RESIM, "color")
            .onAction(c -> colorBlocks())
            .buildAndInstall(tool);
            new ActionBuilder("Foo Bar", getName())
            .menuPath(MENU_RESIM, "Foo bar")
            .menuGroup(MENU_RESIM, "Foo")
            .onAction(c -> fooBar())
            .buildAndInstall(tool);
            new ActionBuilder("About", getName())
            .menuPath(MENU_RESIM, "about")
            .menuGroup(MENU_RESIM, "about")
            .onAction(c -> about())
            .buildAndInstall(tool);
            new ActionBuilder("Resync with server", getName())
             .menuPath(RESimUtilsPlugin.MENU_RESIM, "Refresh", "&Resync with server")
             .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Refresh")
             .onAction(c -> refreshClient(true))
             .buildAndInstall(tool);
            new ActionBuilder("Run to user space", getName())
             .menuPath(RESimUtilsPlugin.MENU_RESIM, "Run to", "&user space")
             .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Run to")
             .onAction(c -> doRESimRefresh("runToUserSpace()"))
             .buildAndInstall(tool);
            new ActionBuilder("Run to text segment", getName())
             .menuPath(RESimUtilsPlugin.MENU_RESIM, "Run to", "&text segment")
             .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Run to")
             .onAction(c -> doRESimRefresh("runToText()"))
             .buildAndInstall(tool);
            new ActionBuilder("Run to syscall", getName())
             .menuPath(RESimUtilsPlugin.MENU_RESIM, "Run to", "&syscall")
             .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Run to")
             .onAction(c -> runToSyscall())
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
            Msg.debug(this,"init plugins registered using registerInit");
            for(RESimProvider provider : initProviders) {
                provider.refresh();
            }



        }
        public Program getProgram() {
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
                if(connected()){
                    Msg.debug(this,  "is TraceActivatedPluginEvent, refresh client");
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
            //}else if(event instanceof TraceRecorderAdvancedPluginEvent) {
            //    Msg.debug(this,  "is trace advanced event");
               // refreshRegisters();

            }else {
                Msg.debug(this,  "plugin event is "+event.getEventName());
            }
            
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
           
            Set<TargetRegisterBank> banks = recorder.getTargetRegisterBanks(current.getThread(), current.getFrame());
            Msg.debug(this, "refreshRegisters got banks");
            for (TargetRegisterBank bank : banks) {
 
                // Now do the same to the bank as before
                try {
                    Msg.debug(this, "refreshRegistrs invalidate caches");
                    bank.invalidateCaches().get();
                    Msg.debug(this, "refreshRegistrs fetch elements");
                    bank.fetchElements(RefreshBehavior.REFRESH_ALWAYS).get();
                    Msg.debug(this, "refreshRegistrs done");

                } catch (InterruptedException | ExecutionException e) {
                    Msg.error(this,  getExceptString(e));
                }
                Msg.debug(this, "refreshRegisters all done");
            }
        }
        public boolean connected() {
           if(impl != null) {
               return true;
            }else {
               return false;
            }
        }
        protected void addThread(java.util.HashMap<Object, Object> entry) {

            Range <Long> r = Range.atLeast(0L);
            try (RecorderPermanentTransaction tid =
                    RecorderPermanentTransaction.start(currentTrace, "Add Thread")) {
                try {
                    TraceThreadManager manager = currentTrace.getThreadManager();
                    Collection<? extends TraceThread> all_threads = manager.getAllThreads();
                    for(TraceThread t : all_threads) {
                        Msg.debug(this,  "thread name "+t.getName()+" path "+t.getPath());
                    }
                    String value = "pid: "+entry.get("pid");
                    //TraceThread thread = manager.addThread(value, r);
                    TraceThread thread = manager.createThread(value, 0);
                    thread.setComment("call: "+entry.get("call"));
                    thread.setCreationSnap(0);
                    
                } catch (DuplicateNameException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }
        protected void manualMap() {
            try {
                getGdbManager();
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            this.doRest();
            this.doMapping();
        }

        protected void colorBlocks() {
            //doThreads();
            Color new_hit_color = new Color(0x00ff00);
            Color old_hit_color = new Color(0x00ffcc);
            Color not_hit_color = new Color(0x00ffff);
            Color pre_hit_color = new Color(0xccff00);
            
            ColorizingService colorizingService = tool.getService(ColorizingService.class);
            String ida_data = System.getenv("RESIM_IDA_DATA");
            if(ida_data == null) {
                Msg.error(this,  "RESIM_IDA_DATA not defined");
                return;
            }
            String hitspath = ida_data+File.separator+program.getName()+File.separator+program.getName();
            String latest_hits_file = hitspath+".hits";
            String all_hits_file = hitspath+".all.hits";
            String pre_hits_file = hitspath+".pre.hits";
            Object latest_json = Json.getJsonFromFile(latest_hits_file);
            if(latest_json == null) {
                Msg.error(this,  "color blocks failed to get json from "+latest_hits_file);
                return;
            }
            ArrayList<Long> new_bb_list = (ArrayList<Long>) latest_json;
            Object all_hits_json = Json.getJsonFromFile(all_hits_file);
            ArrayList<Long> all_bb_list = null;
            if(all_hits_json != null) {
                all_bb_list = (ArrayList<Long>) all_hits_json;
            }else {
                all_bb_list = new ArrayList<Long>();
            }
            ArrayList<Long> pre_bb_list = null;
            Object pre_hits_json = Json.getJsonFromFile(all_hits_file);
            if(pre_hits_json != null) {
                pre_bb_list = (ArrayList<Long>) pre_hits_json;
            }else {
                pre_bb_list = new ArrayList<Long>();
            }
            
            BasicBlockModel bbm = new BasicBlockModel(program);
            int id = program.startTransaction("Test - Color Change");
            CodeBlock cb = null;
            try {
                for(Long bb : new_bb_list) {
                    try {
                        cb = bbm.getCodeBlockAt(addr(bb), TaskMonitor.DUMMY);
                    } catch (CancelledException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                        Msg.error(this,  "color blocks cancled exception "+e.toString());
                        return;
                    }
                    Color hit_color = old_hit_color;
                    if(all_bb_list == null |! all_bb_list.contains(bb)) {
                        hit_color = new_hit_color;
                    }
                    colorizingService.setBackgroundColor(cb.getMinAddress(), cb.getMaxAddress(), hit_color);
                }
               for(Long bb : all_bb_list) {
                    if(new_bb_list.contains((bb))) {
                        continue;
                    }
                    try {
                        cb = bbm.getCodeBlockAt(addr(bb), TaskMonitor.DUMMY);
                    } catch (CancelledException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                        Msg.error(this,  "color blocks cancled exception "+e.toString());
                        return;
                    }
                    colorizingService.setBackgroundColor(cb.getMinAddress(), cb.getMaxAddress(), not_hit_color);
                }
                for(Long bb : all_bb_list) {
                    if(new_bb_list.contains(bb) || all_bb_list.contains(bb)) {
                        continue;
                    }
                    try {
                        cb = bbm.getCodeBlockAt(addr(bb), TaskMonitor.DUMMY);
                    } catch (CancelledException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                        Msg.error(this,  "color blocks cancled exception "+e.toString());
                        return;
                    }
                    colorizingService.setBackgroundColor(cb.getMinAddress(), cb.getMaxAddress(), pre_hit_color);
                }
            } finally {
                    program.endTransaction(id, true);
            }

            program.flushEvents();
            //waitForBusyTool(tool);
        }

        protected void fooBar() {
            
            //doThreads();


        }
        protected void about() {
            JOptionPane.showMessageDialog(plugin.getTool().getActiveWindow(), "RESim plugins version 0.1d",
                    "RESim version", JOptionPane.INFORMATION_MESSAGE);
        }
        private void runToSyscall(){
            String syscall = JOptionPane.showInputDialog(null, "Syscall number (-1 for any)", "-1");
            if(syscall == null){
                Msg.debug(this, "runToSyscall canceled");
            }else{
                String cmd = null;
                if(syscall.equals("-1")){
                    cmd = "runToSyscall()";
                }else{
                    cmd = "runToSyscall("+syscall+")";
                }
                doRESimRefresh(cmd);
            }
        } 
        void revStep(boolean into){
            if(into){
                doRESimRefresh("revStepInto()");
            }else{
                doRESimRefresh("revStepOver()");
            }
       } 
}
