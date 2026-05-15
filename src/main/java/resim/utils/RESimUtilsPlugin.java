package resim.utils;

import docking.DockingUtils;
import docking.action.KeyBindingData;
import docking.action.builder.ActionBuilder;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.KeyStroke;
import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import org.apache.commons.io.FilenameUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import ghidra.app.nav.NavigationUtils;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.debug.api.tracermi.RemoteAsyncResult;
import ghidra.debug.api.tracermi.RemoteMethod;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.file.formats.android.bootldr.AndroidBootLoaderAnalyzer;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.gui.action.PCByRegisterLocationTrackingSpec;
import ghidra.app.plugin.core.debug.gui.register.DebuggerRegistersProvider;
import ghidra.app.plugin.core.debug.gui.register.RegisterRow;
import ghidra.app.services.DebuggerConsoleService;
import ghidra.app.services.DebuggerListingService;
import ghidra.app.services.DebuggerTargetService;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.Swing;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileBytesProvider;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.OptionalHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.demangler.*;
import ghidra.app.util.opinion.CoffLoader;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.services.TraceRmiService;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddress;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceModuleManager;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.trace.database.memory.DBTraceObjectRegisterContainer;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.TraceLocation;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.memory.TraceRegister;
import ghidra.trace.model.memory.TraceRegisterContainer;
//import ghidra.util.database.UndoableTransaction;
import db.Transaction;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;
import java.awt.Color;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.FileWriter;
import java.lang.Thread;
import com.google.common.collect.Range;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.stream.JsonWriter;

@PluginInfo( //
        shortDescription = "RESim Utils", //
        description = "Manage connecting Ghidra to the Simics GDB server, manage the other RESim plugins and provide common functions.", //
        category = PluginCategoryNames.DEBUGGER, //
        packageName = DebuggerPluginPackage.NAME, //
        status = PluginStatus.RELEASED, //
        eventsConsumed = { TraceActivatedPluginEvent.class, //
                TraceClosedPluginEvent.class, //
                TraceSelectionPluginEvent.class, //

        }, //
        servicesRequired = { //
        } //
)
/*
 * Want this plugin to load first. Does not otherwise need to extend Plugin, it
 * has no window
 */
public class RESimUtilsPlugin extends Plugin {
    private PluginTool tool;
    private Program program;
    // private GdbManagerImpl impl;
    private boolean impl = false;
    // GdbModelImpl model;

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
    private Trace current_trace = null;
    protected RESimUtilsPlugin plugin = this;
    private RemoteMethod gdb_execute_method = null;
    private RemoteMethod gdb_registers_refresh_method = null;
    private RemoteMethod gdb_memory_refresh_method = null;
    private List<RegisterValue> latest_register_frame = null;
    private long load_offset = 0;
    private long load_size = 0;
    private String load_string = null;

    /**
     * Construct the RESimUtils plugin.
     * 
     * @param tool the pluginTool that this plugin is added to.
     */
    public RESimUtilsPlugin(PluginTool tool) {
        super(tool);
        this.tool = tool;
        this.program = null;
        // this.impl = null;
        Msg.debug(this, "in resimutils plugin");
        refreshProviders = new ArrayList<RESimProvider>();
        initProviders = new ArrayList<RESimProvider>();

    }

    @Override
    protected void init() {
        Msg.info(this, "in init");
        provider = new RESimUtilsProvider(this);

        createActions();

    }

    public static String getExceptString(Exception e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        String stackTrace = sw.toString();
        return stackTrace;
    }

    public RemoteMethod getGDBExecuteMethod() {
        Msg.debug(this, "getGDBExecuteMethod begin");
        if (gdb_execute_method == null) {

            TraceRmiService model_service;
            Collection<TraceRmiConnection> connection_list;
            TraceRmiConnection the_connect = null;
            String result = null;
            try {
                model_service = tool.getService(TraceRmiService.class);
                connection_list = model_service.getAllConnections();
            } catch (Exception e) {
                Msg.error(this, getExceptString(e));
                return null;
            }
            for (TraceRmiConnection item : connection_list) {
                String des = item.getDescription();
                Msg.debug(this, des);
                if (des.contains("gdb")) {
                    the_connect = item;
                    break;
                }
            }
            if (the_connect != null) {
                gdb_execute_method = the_connect.getMethods().get("execute");
                gdb_registers_refresh_method = the_connect.getMethods().get("refresh_registers");
                gdb_memory_refresh_method = the_connect.getMethods().get("read_mem");

            } else {
                Msg.error(this, "Failed to find the gdb connection.");
            }
        }
        return gdb_execute_method;
    }

    /**
     * Refresh the gdb client state values.
     * 
     */
    public void refreshClient(boolean from_resim) {
        Msg.debug(this, "refreshClient from_resim? " + from_resim);
        if(from_resim){
            doGdbCmd("maint flush register-cache");
            Msg.debug(this, "refreshClient did flush register-cache");
        }
        for(RESimProvider provider : refreshProviders) { 
             Msg.debug(this, "refreshClient refresh a provider"); 
             provider.refresh(); 
        }
        if(from_resim) {
            Msg.debug(this, "refreshClient call doRefresh");
            doRefresh();
        }
        return;
    }

    public Address addr(long addr) {
        /**
         * Get an address in the program memory space.
         * 
         * @param addr The integer address.
         * @return Ghidra address
         */
        AddressSpace statRam = program.getAddressFactory().getDefaultAddressSpace();
        return statRam.getAddress(addr);
    }

    public Address addrDyn(long addr) {
        AddressSpace dynRam = current_trace.getBaseAddressFactory().getDefaultAddressSpace();
        return dynRam.getAddress(addr);

    }

    public void addMessage(String msg) {
        provider.addMessage("RESim:", msg);
    }

    public void myTest() {
       Msg.debug(this, "myTest");
    }
    public List<String> getRegList() {
        DebuggerTraceManagerService traceManager = tool.getService(DebuggerTraceManagerService.class);

        if (traceManager == null || traceManager.getCurrentTrace() == null) {
            System.out.println("No active trace found.");
            return null;
        }

        Trace currentTrace = traceManager.getCurrentTrace();

        // 2. Get the Language object (this defines the registers for the architecture)
        Language language = currentTrace.getBaseLanguage();

        // 3. Get all Register names
        List<String> allNames = language.getRegisterNames();

        // 4. To get specific Register objects (e.g., only base registers)
        List<String> baseRegisterNames = language.getRegisters().stream()
            .filter(Register::isBaseRegister)
            .map(Register::getName)
            .collect(Collectors.toList());

        Msg.debug(this, "Total Registers: " + allNames.size());
        Msg.debug(this, "Base Registers: " + baseRegisterNames);
        return baseRegisterNames;
     
    }

    public CompletableFuture<String> doRESimRefresh(String cmd) {
        /**
         * Use the gdb monitor to send a command to RESim and refresh the client when
         * done.
         * 
         * @param cmd Command to execute
         * @return The response from RESim
         */
        Msg.debug(this, "doRESimRefresh do cmd: " + cmd);
        CompletableFuture<String> cmdfuture = doRESim(cmd);
        String result = null;
        try {
            result = (String) cmdfuture.get();
        } catch (InterruptedException | ExecutionException e) {
            // TODO Auto-generated catch block
            Msg.error(this, getExceptString(e));
            return null;
        }
        Msg.debug(this, "back from cmd get, gotXXXXXXX " + result);
        //try {
        //    Thread.sleep(1000);
        //} catch (InterruptedException e) {
        //    // TODO Auto-generated catch block
        //    e.printStackTrace();
        //}
        Msg.debug(this, "call again bonzo");
        CompletableFuture<String> retval = doRESim("getEIPWhenStopped()");
        Msg.debug(this, "back from getEIPWhenStopped now refesh client");
        refreshClient(true);
        return retval;
    }

    public CompletableFuture<String> doRESim(String cmd) {
        /**
         * Use the gdb monitor to send a command to RESim
         * 
         * @param cmd Command to execute
         * @return The response from RESim
         */
        Msg.debug(this, "in doRESim for cmd "+cmd);
        return doGdbCmd("monitor @cgc." + cmd);
    }
    public CompletableFuture<String> doSimics(String cmd) {
        /**
         * Use the gdb monitor to send a command to Simics
         * 
         * @param cmd Command to execute
         * @return The response from RESim
         */
        Msg.debug(this, "in doSimics for cmd "+cmd);
        return doGdbCmd("monitor " + cmd);
    }

    public CompletableFuture<String> doGdbCmd(String dbg_cmd) {
        /**
         * Send a command to the GDB console.
         * 
         * @param cmd Command to execute
         * @return The response from GDB
         */
        if (gdb_execute_method == null) {
            Msg.error(this, "gdb_execute_method is null");
            return null;
        }
        Msg.debug(this, "in doGdbCmd for cmd "+dbg_cmd);
        return CompletableFuture.supplyAsync(() -> {
            RemoteAsyncResult async_result;
            String result = null;

            async_result = gdb_execute_method.invokeAsync(Map.of("cmd", dbg_cmd, "to_string", true));

            try {
                result = (String) async_result.get();
                Msg.debug(this, "did async_result.get and got len "+result.length());
            } catch (InterruptedException e) {
                // TODO Auto-generated catch block
                Msg.error(this, getExceptString(e));
                Msg.error(this, org.apache.commons.lang3.exception.ExceptionUtils.getStackTrace(e));
            } catch (ExecutionException e) {
                // TODO Auto-generated catch block
                Msg.error(this, getExceptString(e));
                Msg.error(this, org.apache.commons.lang3.exception.ExceptionUtils.getStackTrace(e));
            }
            return result;
        });
    }

    /**
     * Get the current Ghidra debugger trace, may sleep up to 10 seconds if no trace
     * is found.  Sets the global current_trace value.
     * 
     * @return The Trace.
     */
    public Trace getCurrentTrace() {
        DebuggerTraceManagerService traces = tool.getService(DebuggerTraceManagerService.class);

        int failcount = 0;
        while (current_trace == null) {
            current_trace = traces.getCurrentTrace();
            if (current_trace == null) {
                Msg.debug(this, "no current trace, wait a sec");
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                failcount++;
                if (failcount > 10) {
                    return null;
                }
            }
        }
        return current_trace;
    }

    /**
     * Parse a given json string generated by RESim's getSOMap command and use
     * #addModules to add those to the Ghidra modules plugin.
     * 
     * @param all_string The json string from RESim
     */
    protected void parseSO(String all_string) {
        Msg.debug(this, "in parseSO\n");
        // TBD initialize trace from more logical location?
        getCurrentTrace();
        Object obj = Json.getJson(all_string);
        if (obj == null) {
            Msg.debug(this, "Error getting json of somap");
            return;
        }
        java.util.HashMap<Object, Object> somap = (java.util.HashMap<Object, Object>) obj;

        Msg.debug(this, "did hash parseSO\n");
        Msg.debug(this, "size x of hashmap is " + somap.size());
        Msg.debug(this, "call addModule");
        this.addModule(somap);
        Msg.debug(this, "back from addModule");

    }

    protected void addModule(java.util.HashMap<Object, Object> somap) {
        /**
         * Add a module and its sections, as defined by a RESim SO map json, to the
         * Ghidra modules
         * 
         * @param somap The json hashmap
         */
        Msg.debug(this, "in addModule");
        /*
         * ArrayList <java.util.HashMap<Object, Object>> sections=null; try { sections =
         * (ArrayList <java.util.HashMap<Object, Object>>) somap.get("sections"); }catch
         * (Exception e) { Msg.debug(this, getExceptString(e)); }
         * 
         * Long start = 0L; Long end = 0L; Long offset = 0L; Program current_program =
         * getProgram(); String target_path = current_program.getExecutablePath();
         * String target_base = (String) FilenameUtils.getName(target_path);
         * 
         * String prog_path = (String) somap.get("prog_local_path"); String prog_base =
         * (String) FilenameUtils.getName(prog_path); String module_path = null;
         * if(target_base.equals(prog_base)){ String pid_o = (String)
         * somap.get("group_leader");
         * Msg.debug(this,"addModule, is main prog, pid_o is "+pid_o); offset = (Long)
         * somap.get("offset"); //start = (Long) somap.get("prog_start") + offset; start
         * = (Long) somap.get("prog_start"); end = (Long) somap.get("prog_end");
         * module_path = prog_path; }else{
         * Msg.debug(this,"addModule program is not main, search libs for target_base "
         * +target_base+" num sectoins"+sections.size()); String lib_path = null;
         * for(Object o : sections) { java.util.HashMap<Object, Object> section =
         * (java.util.HashMap<Object, Object>) o; lib_path = (String)
         * section.get("local_path"); if(lib_path == null){ lib_path = (String)
         * section.get("file"); } String lib_base = (String)
         * FilenameUtils.getName(lib_path); Msg.debug(this, "check path "+lib_path);
         * if(target_base.startsWith(lib_base) || lib_base.startsWith(target_base)){
         * Msg.debug(this,"addModule found lib that matches prog at "+lib_path);
         * 
         * start = (Long) section.get("locate"); end = (Long) section.get("end");
         * module_path = lib_path; break; } } } if(module_path == null){ Msg.error(this,
         * "Failed to find module for target "+target_path); return; } Msg.debug(this,
         * "get addr path "+module_path+" start: "+String.format("0x%x",
         * start)+" end: "+String.format("0x%x", end)); AddressRangeImpl ar = new
         * AddressRangeImpl(this.addrDyn(start), this.addrDyn(end));
         * 
         * DebuggerModelService modelService =
         * tool.getService(DebuggerModelService.class);
         * 
         * DebuggerTraceManagerService traceManager =
         * tool.getService(DebuggerTraceManagerService.class);
         * 
         * DebuggerCoordinates current_manager = traceManager.getCurrent(); Trace
         * current_trace = traceManager.getCurrentTrace();
         * 
         * TraceModuleManager tm = current_manager.getTrace().getModuleManager();
         * 
         * TraceRecorder recorder =
         * modelService.getRecorder(current_manager.getTrace());
         * 
         * Long snap = recorder.getSnap(); TraceModule progmod = null; String
         * module_base = (String) FilenameUtils.getName(module_path);
         * 
         * DebuggerStaticMappingService mappings =
         * tool.getService(DebuggerStaticMappingService.class); AddressSpace dynRam =
         * current_trace.getBaseAddressFactory().getDefaultAddressSpace(); AddressSpace
         * statRam = current_program.getAddressFactory().getDefaultAddressSpace(); Long
         * length = end - start;
         * 
         * 
         * Msg.debug(this, "start transaction"); try (Transaction tid =
         * currentTrace.openTransaction("Update Module")) {
         * 
         * try { //progmod = tm.getLoadedModuleByPath(snap, module_path);
         * 
         * //Collection<? extends TraceModule> module_collection =
         * tm.getModulesByPath(module_path); //Collection<? extends TraceModule>
         * module_collection = tm.getLoadedModules(snap); Collection<? extends
         * TraceModule> module_collection = tm.getAllModules(); Msg.debug(this,
         * "from loaded modules, got "+module_collection.size()); progmod =
         * module_collection.iterator().next(); Msg.debug(this, "got module"+
         * progmod.getName()+" targetbase "+target_base);
         * 
         * if(progmod == null){ Msg.debug(this,
         * "Failed to find existing module at path "+module_path+" base "
         * +module_base+" count "+module_collection.size()+". Add new module."); progmod
         * = tm.addModule(module_path, target_base, ar, Lifespan.nowOn(0)); }else{
         * progmod.setRange(ar); }
         * 
         * TraceLocation from = new DefaultTraceLocation(current_trace, null,
         * Lifespan.nowOn(0), dynRam.getAddress(start)); ProgramLocation to = new
         * ProgramLocation(current_program, statRam.getAddress(start));
         * DebuggerStaticMappingUtils.addMapping(from, to, length, true);
         * 
         * Msg.debug(this, "did addMapping start "+String.format("0x%x",
         * start)+" length "+length); } catch (Exception e1) { Msg.debug(this,
         * getExceptString(e1)); } } Msg.debug(this, "done transaction");
         * 
         * //Msg.debug(this, "bout to do sections?"); Msg.debug(this,
         * "parseSO, num sections is "+sections.size()); String path = null; String name
         * = null; for(Object o : sections) {
         * 
         * java.util.HashMap<Object, Object> section = (java.util.HashMap<Object,
         * Object>) o; start = (Long) section.get("locate"); end = (Long)
         * section.get("end"); ar = new AddressRangeImpl(this.addrDyn(start),
         * this.addrDyn(end)); path = (String) section.get("local_path"); if(path ==
         * null){ path = (String) section.get("file"); } if(path.equals("unknown")) {
         * continue; } name = FilenameUtils.getName(path); Msg.debug(this,
         * "section path "+path+" start: "+String.format("0x%x",
         * start)+" end: "+String.format("0x%x", end)); //Msg.debug(this,
         * "parseSO add section"); try (Transaction tid =
         * currentTrace.openTransaction("Add Section")) {
         * 
         * try { progmod.addSection(path, name, ar); //Msg.debug(this,
         * "did add section "+path); } catch (DuplicateNameException e) { // TODO
         * Auto-generated catch block //e.printStackTrace(); } //Msg.debug(this,
         * "parseSO back from add section"); } }
         */
    }

    public void doMapping() {
        /**
         * Get program information from RESim and use it to map static/dynamic listings.
         *
         */
        Msg.debug(this, "in doMapping");
        String cmd = "getSOMap()";
        doRESim(cmd).thenApply(so_json -> {
            if (so_json != null) {
                this.parseSO(so_json);
                didMapping = true;
            } else {
                Msg.error(this, "Failed to getSOMap");
            }
            return so_json;
        });
    }

    public void doThreads() {
        /**
         * Get thread information from RESim and add it to ghidra's threads.
         *
         */
        Msg.debug(this, "in doThreads");
        String cmd = "getThreads()";
        doRESim(cmd).thenApply(thread_json -> {
            if (thread_json != null) {
                parseThreads(thread_json);
            } else {
                Msg.error(this, "Failed to getThreads");
            }
            return thread_json;
        });
    }

    protected void parseThreads(String all_string) {
        Msg.debug(this, "in parseThreads json:");
        Msg.debug(this, all_string);
        // TBD initialize trace from more logical location?
        getCurrentTrace();
        Object obj = Json.getJson(all_string);
        if (obj == null) {
            Msg.debug(this, "parseThreads, Error getting json of threads");
            return;
        }
        ArrayList<java.util.HashMap<Object, Object>> threads = null;
        try {
            threads = (ArrayList<java.util.HashMap<Object, Object>>) obj;
        } catch (Exception e) {
            Msg.debug(this, getExceptString(e));
        }
        try (Transaction tid = current_trace.openTransaction("Get Thread")) {
            TraceThreadManager manager = current_trace.getThreadManager();
            Collection<? extends TraceThread> all_threads = manager.getAllThreads();
            for (TraceThread t : all_threads) {
                Msg.debug(this, "thread name " + t.getName(0) + " path " + t.getPath());
            }
        }
        for (java.util.HashMap<Object, Object> t : threads) {
            addThread(t);
        }

    }

    String writeGDBMappingMacro() {
        String retval = null;
        String tmpdir = System.getProperty("java.io.tmpdir");
        System.out.println("Temp file path: " + tmpdir);
        List<String> content = Arrays.asList("define info proc mappings", "echo 0x0 0x0 0xbfffffff 0x0 lomem \\n",
                "echo 0xc0000000 0xfffffff 0x800000 0x0 himem", "end");

        try {

            // Create an temporary file
            Path temp = Files.createTempFile("32bit", ".mapping");
            System.out.println("Temp file : " + temp);

            Files.write(temp, content, StandardOpenOption.CREATE);
            retval = temp.toString();

        } catch (IOException e) {
            e.printStackTrace();
        }
        return retval;
    }

    String writeGDBMapping64Macro() {
        String retval = null;
        String tmpdir = System.getProperty("java.io.tmpdir");
        System.out.println("Temp file path: " + tmpdir);
        List<String> content = Arrays.asList("define info proc mappings",
                "echo 0x0 0x7FFFFFFFFFFFFFFF 0x8000000000000000 0x0 lomem \n",
                "echo 0x8000000000000000 0xFFFFFFFFFFFFFFFF 0x8000000000000000 0x0 himem", "end");

        try {

            // Create an temporary file
            Path temp = Files.createTempFile("64bit", ".mapping");
            System.out.println("Temp file : " + temp);

            Files.write(temp, content, StandardOpenOption.CREATE);
            retval = temp.toString();

        } catch (IOException e) {
            e.printStackTrace();
        }
        return retval;
    }

    public void attachDebug() {
        /*
         * CompletableFuture <? extends GdbManagerImpl>gdb_manager = createDebug();
         * gdb_manager.thenApply(manager -> {
         * 
         * CompletableFuture<String> attach_result = attachTarget(); return
         * attach_result.thenApply(y -> { Msg.debug(this, "no defined arch, do attach");
         * return y; });
         * 
         * });
         */
    }

    public void doRest() {
        program = getProgram();
        if (program == null) {
            Msg.error(this, "Failed to get program");
        } else {
            initOtherPlugins();

            Msg.debug(this, "Finished initializing the registered plugins.");
        }
    }

    public void setHostPort() {
        String orig_host_port = Preferences.getProperty(RESIM_HOST_PORT);
        String host_port = JOptionPane.showInputDialog(null, "Enter host:port", orig_host_port);
        if (host_port == null) {
            host_port = orig_host_port;
        }
        Preferences.setProperty(RESIM_HOST_PORT, host_port);
    }

    public void setGdbPath() {
        String gdbpath = Preferences.getProperty(RESIM_GDB_PATH);
        JFileChooser fc = new JFileChooser(gdbpath);
        int got = fc.showOpenDialog(tool.getActiveWindow());
        if (got == JFileChooser.APPROVE_OPTION) {
            File selected = fc.getSelectedFile();
            Preferences.setProperty(RESIM_GDB_PATH, selected.toString());
        }
    }

    public void setFSRootPath() {
        String fsroot = Preferences.getProperty(RESIM_FSROOT_PATH);
        JFileChooser fc = new JFileChooser(fsroot);
        fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int got = fc.showOpenDialog(tool.getActiveWindow());
        if (got == JFileChooser.APPROVE_OPTION) {
            File selected = fc.getSelectedFile();
            Preferences.setProperty(RESIM_FSROOT_PATH, selected.toString());
        }
    }

    public void setTargetArch() {
        String target = Preferences.getProperty(RESIM_TARGET_ARCH);
        if (target == null) {
            target = "auto";
        }

        Object[] choices = { "auto", "armv7" };
        String s = (String) JOptionPane.showInputDialog(null, "Select target architecture:", "Target Selection",
                JOptionPane.PLAIN_MESSAGE, null, choices, target);
        if (s != null) {
            Preferences.setProperty(RESIM_TARGET_ARCH, s);
            Msg.debug(this, "target arch set to " + s);
        }

    }

    private void createActions() {
        /*
         * Cursor and register actions for right-click menu popups. Also see actions
         * defined in bookmarks, e.g., revTaint functions that generate bookmarks.
         */
        tool.setMenuGroup(new String[] { RESIM_MENU_PULLRIGHT }, RESIM_MENU_SUBGROUP, RESIM_SUBGROUP_MIDDLE);
        RESimCursorAction revToCursorAction = new RESimCursorAction("Rev to cursor", "revToAddr", this, null, true);
        revToCursorAction.setKeyBindingData(
                new KeyBindingData(KeyStroke.getKeyStroke(KeyEvent.VK_F4, InputEvent.SHIFT_DOWN_MASK)));
        tool.addAction(revToCursorAction);

        RESimCursorAction runToCursorAction = new RESimCursorAction("Run to cursor", "doBreak", this, null, true);
        runToCursorAction.setKeyBindingData(
                new KeyBindingData(KeyStroke.getKeyStroke(KeyEvent.VK_F4, DockingUtils.CONTROL_KEY_MODIFIER_MASK)));
        tool.addAction(runToCursorAction);

        RESimRegAction revModRegAction = new RESimRegAction("Rev mod register", "revToModReg", this, null);
        tool.addAction(revModRegAction);
        RESimCursorAction revModAddrAction = new RESimCursorAction("Rev mod address", "revToWrite", this, null);
        tool.addAction(revModAddrAction);

        tool.setMenuGroup(new String[] { MENU_RESIM, "RESim" }, "first");

        RESimListingGoToAction lc = new RESimListingGoToAction("Goto address", this);
        tool.addAction(lc);

        new ActionBuilder("Manual map", getName()).menuPath(MENU_RESIM, "Manual map").menuGroup(MENU_RESIM, "map")
                .onAction(c -> manualMap()).buildAndInstall(tool);

        /*
         * Main menu RESim entries
         */
        //new ActionBuilder("my test", getName()).menuPath(MENU_RESIM, "my test")
        //        .menuGroup(MENU_RESIM, "Attach").onAction(c -> myTest())
        //       .keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_R, InputEvent.SHIFT_DOWN_MASK)).buildAndInstall(tool);
        new ActionBuilder("Reverse step into", getName()).menuPath(RESimUtilsPlugin.MENU_RESIM, "Reverse", "&Step-into")
                .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Reverse").onAction(c -> doRESimRefresh("revStepInto()"))
                .keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_F8, InputEvent.CTRL_DOWN_MASK)).buildAndInstall(tool);
        new ActionBuilder("Reverse step over", getName()).menuPath(RESimUtilsPlugin.MENU_RESIM, "Reverse", "&Step-over")
                .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Reverse").onAction(c -> doRESimRefresh("revStepOver()"))
                .keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_F10, InputEvent.CTRL_DOWN_MASK)).buildAndInstall(tool);
        new ActionBuilder("Reverse to text", getName()).menuPath(RESimUtilsPlugin.MENU_RESIM, "Reverse", "&to text")
                .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Reverse").onAction(c -> doRESimRefresh("revToText()"))
                .buildAndInstall(tool);
        new ActionBuilder("Color blocks", getName()).menuPath(MENU_RESIM, "Color blocks").menuGroup(MENU_RESIM, "color")
                .onAction(c -> colorBlocks()).buildAndInstall(tool);
        new ActionBuilder("Dump Artifacts", getName()).menuPath(MENU_RESIM, "Dump artifacts")
                .menuGroup(MENU_RESIM, "artifacts").onAction(c -> dumpArtifacts()).buildAndInstall(tool);
        //new ActionBuilder("Foo Bar", getName()).menuPath(MENU_RESIM, "Foo bar").menuGroup(MENU_RESIM, "Foo")
        //       .onAction(c -> fooBar()).buildAndInstall(tool);
        new ActionBuilder("About", getName()).menuPath(MENU_RESIM, "about").menuGroup(MENU_RESIM, "about")
                .onAction(c -> about()).buildAndInstall(tool);
        new ActionBuilder("Resync with server", getName())
                .menuPath(RESimUtilsPlugin.MENU_RESIM, "Refresh", "&Resync with server")
                .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Refresh").onAction(c -> refreshClient(true))
                .buildAndInstall(tool);
        new ActionBuilder("Run to user space", getName()).menuPath(RESimUtilsPlugin.MENU_RESIM, "Run to", "&user space")
                .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Run to").onAction(c -> doRESimRefresh("runToUserSpace()"))
                .buildAndInstall(tool);
        new ActionBuilder("Run to text segment", getName())
                .menuPath(RESimUtilsPlugin.MENU_RESIM, "Run to", "&text segment")
                .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Run to").onAction(c -> doRESimRefresh("runToText()"))
                .buildAndInstall(tool);
        new ActionBuilder("Run to syscall", getName()).menuPath(RESimUtilsPlugin.MENU_RESIM, "Run to", "&syscall")
                .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Run to").onAction(c -> runToSyscall()).buildAndInstall(tool);

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
            if (p.getClass() == RESimUtilsPlugin.class) {
                resimUtils = (RESimUtilsPlugin) p;
                break;
            }
        }

        if (resimUtils == null) {
            Msg.out("No resimUtils, bail");
        }
        return resimUtils;
    }

    public void registerRefresh(RESimProvider provider) {
        /**
         * Register a RESim plugin to be refreshed each time program state changes.
         */
        if (impl == false) {
            Msg.debug(this, "register plugin for refresh");
            refreshProviders.add(provider);
        } else {
            Msg.debug(this, "registerRefresh Already connected, just refresh the plugin.");
            provider.refresh();
        }
    }

    public void registerInit(RESimProvider provider) {
        /**
         * Register a RESim plugin to be initialized when the debugger is attached.
         */
        if (impl == false) {
            Msg.debug(this, "register plugin for init ");
            initProviders.add(provider);
        } else {
            Msg.debug(this, "registerInit Already connected, just refresh the plugin.");
            provider.refresh();
        }
    }

    private void initOtherPlugins() {
        /**
         * Refresh plugins registered using registerInit
         */
        Msg.debug(this, "init plugins registered using registerInit");
        for (RESimProvider provider : initProviders) {
            provider.refresh();
        }

    }

    public Program getProgram() {
        ProgramManager pm = null;
        int failcount = 0;
        while (pm == null) {
            pm = tool.getService(ProgramManager.class);
            if (pm == null) {
                Msg.debug(this, "no Program manager, wait a sec");
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    Msg.error(this, getExceptString(e));
                }
                failcount++;
                if (failcount > 10) {
                    return null;
                }
            }
        }
        if (pm != null) {
            return pm.getCurrentProgram();
        }
        Msg.error(this, "getProgram failed");
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
            Msg.debug(this, "is TraceActivatedPluginEvent");
            getGDBExecuteMethod();
            getCurrentTrace();
            if (connected()) {
                Msg.debug(this, "is TraceActivatedPluginEvent, refresh client");
                if(program == null){
                    program = getProgram();
                }
                refreshClient(true);
                getLoadOffset();
            }
        } else if (event instanceof TraceSelectionPluginEvent) {
            Msg.debug(this, "is traceSelection");
            if (program == null) {
                Msg.debug(this, "program is null, call getProgram");
                program = getProgram();
            }
            if (!didMapping && impl != false) {
                // Do mapping as callback here, otherwise, mapping is attempted
                // before ghidra debugger settles out.
                doRest();
                doMapping();
                tool.getService(DebuggerListingService.class)
                        .setTrackingSpec(PCByRegisterLocationTrackingSpec.INSTANCE);
            }
            // }else if(event instanceof TraceRecorderAdvancedPluginEvent) {
            // Msg.debug(this, "is trace advanced event");
            // refreshRegisters();

        } else {
            Msg.debug(this, "plugin event is " + event.getEventName());
        }

    }
    protected DebuggerTargetService getTargetService() {
        DebuggerTargetService targetService = tool.getService(DebuggerTargetService.class);
            return targetService;
    }
    public Long getRegValue(String reg){
        Long retval = (Long) null;
        Msg.debug(this, "getRegValue for reg "+reg);
        if(latest_register_frame != null){
            for (RegisterValue reg_value : latest_register_frame) {
                Register register = reg_value.getRegister();
                Msg.debug(this, "check against "+register.getName());
                if(register.getName().equals(reg)){
                    Msg.debug(this, "getRegValue found for reg "+reg);
                    retval = reg_value.getUnsignedValue().longValue();
                    break;
                }
            }
        }else{
            Msg.debug(this, "getRegValue, latest_register_frame is null");
        }
        return retval;
    }
    protected RemoteAsyncResult readCurrentFrame(DebuggerCoordinates current, boolean forceRefresh) {
        //List<String> REG_NAMES = List.of("r1", "r2", "pc");
        List<String> REG_NAMES = getRegList();
        long snap = current.getSnap();
        TracePlatform platform = current.getPlatform();
        List<Register> regs = REG_NAMES.stream().map(platform.getLanguage()::getRegister).toList();
        TraceThread thread = current.getThread();
        int frame = current.getFrame(); 

        //if (forceRefresh) {
        //        setUnknown(platform, thread, frame, snap, regs);
        //}
        Msg.debug(this, "call readRegisters");
        List<RegisterValue> value_list = readRegisters(platform, thread, frame, snap, regs);
        //for (RegisterValue reg_value : value_list) {
        //        Msg.debug(this, "readCurrentFrame value is "+reg_value);
        //}
        Msg.debug(this, "back from readRegisters");
        latest_register_frame = value_list;
        //Msg.debug(this, "doReadCurrentFrame call to readCurrentFrame got "+latest_register_frame.toString());
        return (RemoteAsyncResult) value_list;
    }
    protected List<RegisterValue> readRegisters(TracePlatform platform, TraceThread thread, int frame,
                        long snap, Collection<Register> registers) {
                Msg.debug(this, "readRegisters call refreshRegisersIfLive");
                refreshRegistersIfLive(platform, thread, frame, snap, registers);
                TraceMemorySpace regs =
                        thread.getTrace().getMemoryManager().getMemoryRegisterSpace(thread, frame, false);
                if (regs == null) {
                        Msg.debug(this, "readRegisters regs is null");
                        return registers.stream().map(RegisterValue::new).collect(Collectors.toList());
                }
                return registers.stream().map(r -> regs.getValue(snap, r)).collect(Collectors.toList());
    }

    protected void setUnknown(TracePlatform platform, TraceThread thread, int frame, long snap,
                        List<Register> regs) {
                TraceMemorySpace regSpace = thread
                                .getTrace()
                                .getMemoryManager()
                                .getMemoryRegisterSpace(thread, frame, false);
                if (regSpace == null) {
                        Msg.debug(this, "setUnknown regSpace is null");
                        return;
                }
                for (Register reg : regs) {
                        Msg.debug(this, "setUnknown state for reg "+reg);
                        regSpace.setState(platform, snap, reg, TraceMemoryState.UNKNOWN);
                }
        
    } 
    protected void refreshRegistersIfLive(TracePlatform platform, TraceThread thread, int frame,
                        long snap, Collection<Register> registers) {
                Trace trace = thread.getTrace();

                Target target = getTargetService().getTarget(trace);
                if (target == null || target.getSnap() != snap) {
                        return;
                }
                Set<Register> asSet = registers instanceof Set<Register> s ? s : Set.copyOf(registers);
                target.readRegisters(platform, thread, frame, asSet);
    }
    public CompletableFuture<String> doReadCurrentFrame(DebuggerCoordinates current, boolean forceRefresh) {
        /**
         */
        return CompletableFuture.supplyAsync(() -> {
            RemoteAsyncResult async_result;
            String result = null;
            Msg.debug(this, "In doReadCurrentFrame");
            async_result = readCurrentFrame(current, forceRefresh);

            try {
                result = (String) async_result.get();
            } catch (InterruptedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (ExecutionException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            return result;
        });
    }
    public CompletableFuture<String> doRefresh() {
        /**
         */
        if (gdb_execute_method == null) {
            Msg.error(this, "gdb_execute_method is null");
            return null;
        }
        return CompletableFuture.supplyAsync(() -> {
            RemoteAsyncResult async_result = null;
            String result = null;

            //newRefreshRegisters();
            refreshFrameRegisters();
            //refreshMemory();

            try {
                result = (String) async_result.get();
            } catch (InterruptedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (ExecutionException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            return result;
        });
    }

    public void newRefreshRegisters(){
        // NOT USED
        DebuggerTraceManagerService traceManager = tool.getService(DebuggerTraceManagerService.class);

        DebuggerCoordinates current = traceManager.getCurrent();
        Trace currentTrace = traceManager.getCurrentTrace();
        Collection<? extends TraceThread> threads = currentTrace.getThreadManager().getAllThreads();
        for (TraceThread currentThread : threads) {
            Msg.debug(this,  "check thread "+currentThread.getName(0)+" path "+currentThread.getPath());
            TraceObject threadObj = currentThread.getObject();
        
            // Format the thread name to match how it appears in the canonical path (e.g., "[1]")
            String threadPathPart = "[" + currentThread.getName(0) + "]";
        
            // 3. Search the TraceObject stream for the exact schema the RMI method expects
            Optional<? extends TraceObject> regNode = currentTrace.getObjectManager()
                .getAllObjects()
                .filter(obj -> "RegisterValueContainer".equals(obj.getSchema().getName().toString()))
                //.filter(obj -> obj.getCanonicalPath().toString().contains(threadPathPart))
                .findFirst();
        
            // 4. Invoke the method on the found node
            if (regNode.isPresent()) {
                Msg.debug(this, "regNode is present, name "+regNode.toString());
                gdb_registers_refresh_method.invoke(Map.of("node", regNode.get()));
            } else {
                Msg.warn(this, "Could not find a RegisterValueContainer for thread " + currentThread.getName(0));
            }
        }
    }
    public void refreshMemory(){
        // NOT USED
        DebuggerTraceManagerService traceManager = tool.getService(DebuggerTraceManagerService.class);
        Msg.debug(this, "in refreshMemory");
        DebuggerCoordinates current = traceManager.getCurrent();
        Trace currentTrace = traceManager.getCurrentTrace();
        Collection<? extends TraceThread> threads = currentTrace.getThreadManager().getAllThreads();
        for (TraceThread currentThread : threads) {
            Msg.debug(this,  "check thread "+currentThread.getName(0)+" path "+currentThread.getPath());
            TraceObject threadObj = currentThread.getObject();
        
            // Format the thread name to match how it appears in the canonical path (e.g., "[1]")
            String threadPathPart = "[" + currentThread.getName(0) + "]";
        
            // 3. Search the TraceObject stream for the exact schema the RMI method expects
            Optional<? extends TraceObject> memoryNode = currentTrace.getObjectManager()
                .getAllObjects()
                .filter(obj -> "Memory".equals(obj.getSchema().getName().toString()))
                .findFirst();
        
            // 4. Invoke the method on the found node
            if (memoryNode.isPresent()) {
                Msg.debug(this, "memoryNode is present, name "+memoryNode.toString());
                gdb_memory_refresh_method.invoke(Map.of("node", memoryNode.get()));
            } else {
                Msg.warn(this, "Could not find a Memory schema enrty for thread " + currentThread.getName(0));
            }
        }
    }
    public void refreshFrameRegisters() {
        Msg.debug(this, "refreshFrameRegisters");
        DebuggerTraceManagerService traceManager = tool.getService(DebuggerTraceManagerService.class);

        DebuggerCoordinates current = traceManager.getCurrent();
        Msg.debug(this,"call doReadCurrentFrame");
        try (Transaction tx = current.getTrace().openTransaction("Refresh Registers")) {
                //readCurrentFrame(current, true);
                CompletableFuture<String> result = doReadCurrentFrame(current, true);
        }
        return;
    }

    public boolean connected() {
        if (gdb_execute_method != null) {
            return true;
        } else {
            return false;
        }
    }

    protected void addThread(java.util.HashMap<Object, Object> entry) {

        Range<Long> r = Range.atLeast(0L);
        try (Transaction tid = current_trace.openTransaction("Add Thread")) {
            try {
                TraceThreadManager manager = current_trace.getThreadManager();
                Collection<? extends TraceThread> all_threads = manager.getAllThreads();
                for (TraceThread t : all_threads) {
                    Msg.debug(this, "thread name " + t.getName(0) + " path " + t.getPath());
                }
                String value = "pid: " + entry.get("pid");
                // TraceThread thread = manager.addThread(value, r);
                TraceThread thread = manager.createThread(value, 0);
                thread.setComment(0, "call: " + entry.get("call"));
                // thread.setCreationSnap(0);

            } catch (DuplicateNameException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }

    protected void manualMap() {

        try {
            // getGdbManager();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        // this.doRest();
        this.doMapping();
    }

    public Long getCoffOriginalImageBase() {
        long retval = -1l;
        Msg.info(this, "ingetCoffOrig...");
        List<FileBytes> allFileBytes = program.getMemory().getAllFileBytes();
        if (allFileBytes.isEmpty()) {
            Msg.error(this, "Unable to retrieve Program header: no FileBytes", null);
            return -1l;
        }
        FileBytes fileBytes = allFileBytes.get(0); // Should be that of main imported file
        ByteProvider bprovider = new FileBytesProvider(fileBytes); // close not required
        try {
            PortableExecutable pe = new PortableExecutable(bprovider, SectionLayout.FILE, true, true);
            NTHeader ntHeader = pe.getNTHeader(); // will be null if header parse fails
            if (ntHeader == null) {
                Msg.error(this, "Unable to retrieve NTHeader from PE", null);
                return -1l;
            }
            OptionalHeader optionalHeader = ntHeader.getOptionalHeader();
            retval = optionalHeader.getImageBase();
        } catch (RuntimeException ex) {
            Msg.error(this, ex.getMessage());
        } catch (IOException e) {
            // TODO Auto-generated catch block
            Msg.error(this, e.getMessage());

            e.printStackTrace();
        }
        return retval;
    }

    protected void rebase(long offset) {
        Msg.info(this, "do rebase");
        Address base_addr = this.addr(offset);
        int t = program.startTransaction("rebase");

        try {
            program.setImageBase(base_addr, false);
        } catch (AddressOverflowException | LockException | IllegalStateException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        program.endTransaction(t, true);

    }

    protected void dumpArtifacts() {
        program = getProgram();
        // String target_root = System.getenv("target_root");
        String target_root = Preferences.getProperty(RESIM_FSROOT_PATH);

        if (target_root == null) {
            Msg.error(this, "target_root not defined");
            JOptionPane.showMessageDialog(plugin.getTool().getActiveWindow(),
                    "Missing TARGET_ROOT env variable.  Start Ghidra using runGhidra.sh from application root directory.",
                    "Missing TARGET_ROOT path", JOptionPane.ERROR_MESSAGE);
            return;
        }
        String ida_analysis = System.getenv("IDA_ANALYSIS");
        // String ida_analysis = "/tmp/myanalysis";
        if (ida_analysis == null) {
            Msg.error(this, "ida_analysis not defined");
            JOptionPane.showMessageDialog(plugin.getTool().getActiveWindow(),
                    "Missing IDA_ANALYSIS env variable.  Start Ghidra using runGhidra.sh from application root directory.",
                    "Missing IDA_ANALYSIS path", JOptionPane.ERROR_MESSAGE);
            return;
        }
        String target_image_path = program.getExecutablePath();
        String relative = null;
        if (target_image_path.startsWith(target_root)) {
            relative = target_image_path.substring(target_root.length());
            Msg.debug(this, "relative " + relative);
        } else {
            Msg.error(this, "target image path " + target_image_path + " does not start with root " + target_root);
            JOptionPane.showMessageDialog(plugin.getTool().getActiveWindow(),
                    "target image path " + target_image_path + " does not start with root " + target_root,
                    "Missing TARGET_ROOT path", JOptionPane.ERROR_MESSAGE);
            return;
        }
        long orig_base = 0;
        try {
            orig_base = ElfLoader.getElfOriginalImageBase(program);
        } catch (NullPointerException ex) {
            Msg.info(this, "Not elf, try pe");
            orig_base = getCoffOriginalImageBase();
        }
        long current_base = program.getImageBase().getOffset();
        rebase(orig_base);
        Msg.info(this, "orig image base " + orig_base + " current base " + current_base);
        File root_file = new File(target_root);
        String base_name = root_file.getName();
        File analysis_file = new File(ida_analysis + File.separator + base_name + relative);
        String analysis_parent = analysis_file.getParent();
        File parent_file = new File(analysis_parent);
        parent_file.mkdirs();
        String outfuns = ida_analysis + File.separator + base_name + relative + ".funs";
        String outblocks = ida_analysis + File.separator + base_name + relative + ".blocks";
        long delta = current_base - orig_base;
        dumpFunctions(outfuns);
        dumpBlocks(outblocks);
        String outexternals = ida_analysis + File.separator + base_name + relative + ".imports";
        dumpExternals(outexternals);
        String outxrefs = ida_analysis + File.separator + base_name + relative + ".arm_blr";
        dumpArmBlrXrefs(outxrefs);
        rebase(current_base);

    }

    protected void dumpFunctions(String outpath) {
        program = getProgram();
        String architecture = program.getLanguage().getProcessor().toString();
        Msg.info(this, "architecture is " + architecture);

        File outputFile = new File(outpath);
        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        JsonWriter jsonWriter = null;
        try {
            jsonWriter = new JsonWriter(new FileWriter(outputFile));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        JsonObject thefuns = new JsonObject();
        FunctionManager fm = program.getFunctionManager();
        for (Function f : fm.getFunctions(true)) {
            Address min = f.getBody().getMinAddress();
            Address max = f.getBody().getMaxAddress();
            JsonObject function = new JsonObject();

            String fname = f.getName();
            /*
             * DemangledObject demo = DemanglerUtil.demangle(f.getName()); if(demo != null)
             * { fname = demo.getDemangledName(); Msg.info(this, "demangled to "+fname); }
             */
            int adjust = adjustStack(f, architecture);

            function.addProperty("name", fname);
            function.addProperty("start", min.getOffset());
            function.addProperty("end", max.getOffset());
            function.addProperty("adjust_sp", adjust);
            String fun_addr = String.valueOf(min.getOffset());
            thefuns.add(fun_addr, function);
        }
        gson.toJson(thefuns, jsonWriter);
        try {
            jsonWriter.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Msg.info(this, "Json of functions written to " + outpath);
    }

    protected boolean isArm(String arch) {
        if (arch.equals("AARCH64") || arch.equals("ARM")) {
            return true;
        } else {
            return false;
        }
    }

    protected int getValue(String token) {
        int retval = 0;
        token = token.strip();
        if (token.startsWith("#")) {
            token = token.substring(1);
        }
        retval = Integer.decode(token);
        return retval;
    }

    protected int adjustStack(Function fun, String architecture) {
        int adjust = 0;
        program = getProgram();
        AddressIterator iter = fun.getBody().getAddresses(false);
        int max_look = 10;
        int counter = 0;
        boolean got_ret = false;
        for (Address inst_addr : iter) {
            Instruction instruct = program.getListing().getInstructionAt(inst_addr);
            if (instruct == null) {
                continue;
            }
            String s = instruct.getMnemonicString().toLowerCase();
            // Msg.info(this, "addr "+inst_addr+" instruct string "+s);

            if (got_ret == false) {
                if (!s.equals("ret")) {
                    continue;
                } else {
                    // Msg.info(this, "got ret");
                    got_ret = true;
                }
            }
            if (s.startsWith("add")) {
                String op0 = instruct.getDefaultOperandRepresentation(0).toLowerCase();
                if (op0.equals("sp")) {
                    if (isArm(architecture)) {
                        String op2_s = instruct.getDefaultOperandRepresentation(2).toLowerCase();
                        int op2 = getValue(op2_s);
                        adjust = adjust + op2;
                    } else {
                        String op1_s = instruct.getDefaultOperandRepresentation(1).toLowerCase();
                        int op1 = getValue(op1_s);
                        adjust = adjust + op1;

                    }
                }

            } else if (isArm(architecture) && s.startsWith("l")) {
                String addr_op = null;
                if (s.startsWith("ldp")) {
                    addr_op = instruct.getDefaultOperandRepresentation(2).toLowerCase();
                } else {
                    addr_op = instruct.getDefaultOperandRepresentation(1).toLowerCase();
                }
                // Msg.info(this, "addr op is "+addr_op);
                if (addr_op.contains("],")) {
                    int index = addr_op.indexOf("],") + 2;
                    String rest = addr_op.substring(index);
                    // Msg.info(this, "value string is "+rest);
                    int this_adjust = getValue(rest);
                    // Msg.info(this, "value value is"+this_adjust);
                    adjust = adjust + this_adjust;
                    break;
                }
            }

            counter = counter + 1;
            if (counter > max_look) {
                break;
            }
        }
        return adjust;
    }

    protected void dumpExternals(String outpath) {
        program = getProgram();
        File outputFile = new File(outpath);
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        JsonWriter jsonWriter = null;
        try {
            jsonWriter = new JsonWriter(new FileWriter(outputFile));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        JsonObject thefuns = new JsonObject();
        FunctionManager fm = program.getFunctionManager();
        String fun_addr = null;
        for (Function f : fm.getExternalFunctions()) {
            String sig = f.getSignature().getPrototypeString();
            String ret_type = f.getSignature().getReturnType().getDisplayName();
            String fname = f.getName();
            sig = sig.substring(ret_type.length()).trim();

            // Msg.info(this, "sig "+sig+" ret type "+ ret_type);
            // thanks dev747368!
            Address[] ex_link = NavigationUtils.getExternalLinkageAddresses(program, f.getEntryPoint());
            for (Address ax : ex_link) {
                // Msg.info(this, "link addr val "+val);
                fun_addr = String.valueOf(ax.getOffset());
                Msg.info(this, "fun " + fname + " link addr " + ax);

            }
            // tbd names are demangled already, remove this?
            DemangledObject demo = DemanglerUtil.demangle(program, sig);
            if (demo != null) {
                sig = demo.getName();
                Msg.info(this, "demangled to " + sig);
            } else {
                // Msg.info(this, "no demangle for "+fname);
            }

            thefuns.addProperty(fun_addr, sig);

        }
        gson.toJson(thefuns, jsonWriter);
        try {
            jsonWriter.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Msg.info(this, "Json of imports written to " + outpath);
    }

    protected void dumpArmBlrXrefs(String outpath) {
        program = getProgram();
        File outputFile = new File(outpath);
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        JsonWriter jsonWriter = null;
        try {
            jsonWriter = new JsonWriter(new FileWriter(outputFile));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        JsonObject arm_blr = new JsonObject();
        FunctionManager fm = program.getFunctionManager();
        SymbolTable st = program.getSymbolTable();
        for (Function f : fm.getExternalFunctions()) {
            String sig = f.getSignature().getPrototypeString();
            String ret_type = f.getSignature().getReturnType().getDisplayName();
            String fname = f.getName();
            sig = sig.substring(ret_type.length()).trim();

            // Msg.info(this, "sig "+sig+" ret type "+ ret_type);
            // thanks dev747368!
            Address[] ex_link = NavigationUtils.getExternalLinkageAddresses(program, f.getEntryPoint());
            for (Address ax : ex_link) {
                // Msg.info(this, "link addr val "+val);
                // Msg.info(this, "fun "+fname+" link addr "+ax);

                ReferenceIterator references = program.getReferenceManager().getReferencesTo(ax);
                while (references.hasNext()) {
                    Reference reference = references.next();
                    Address from = reference.getFromAddress();
                    // Msg.info(this, "ref addr from "+from);
                    long next_pc = from.getOffset() + 4;
                    Instruction instruct = program.getListing().getInstructionAt(addr(next_pc));
                    if (instruct == null) {
                        continue;
                    }
                    String s = instruct.getMnemonicString().toLowerCase();
                    // Msg.info(this, "ref instruct "+s);
                    int counter = 0;
                    while (!(s.startsWith("blr") || s.startsWith("br"))) {
                        next_pc = next_pc + 4;
                        counter = counter + 1;
                        if (counter > 10) {
                            break;
                        }
                        instruct = program.getListing().getInstructionAt(addr(next_pc));
                        if (instruct != null) {
                            s = instruct.getMnemonicString().toLowerCase();
                            // Msg.info(this, "next_pc instruct "+s);
                        }

                    }
                    // Msg.info(this, "after break s is "+s);
                    if (s.startsWith("blr") || s.startsWith("br")) {
                        arm_blr.addProperty(String.valueOf(next_pc), fname);
                    }
                }

            }

        }
        gson.toJson(arm_blr, jsonWriter);
        try {
            jsonWriter.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Msg.info(this, "Json of arm blr xrefs written to " + outpath);
    }

    protected void dumpBlocks(String outpath) {
        program = getProgram();
        File outputFile = new File(outpath);
        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        JsonWriter jsonWriter = null;
        try {
            jsonWriter = new JsonWriter(new FileWriter(outputFile));
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        JsonObject theblocks = new JsonObject();

        BasicBlockModel bbm = new BasicBlockModel(program);
        FunctionManager fm = program.getFunctionManager();
        for (Function f : fm.getFunctions(true)) {
            Address min = f.getBody().getMinAddress();
            Address max = f.getBody().getMaxAddress();
            AddressSetView set = new AddressSet(min, max);
            CodeBlockIterator cbi = null;
            try {
                cbi = bbm.getCodeBlocksContaining(set, TaskMonitor.DUMMY);
            } catch (CancelledException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            JsonObject function = new JsonObject();
            function.addProperty("name", min.getOffset());
            JsonArray funblocks = new JsonArray();
            for (CodeBlock cb : cbi) {
                Address block_min = cb.getMinAddress();
                Address block_max = cb.getMaxAddress();
                JsonObject block = new JsonObject();
                block.addProperty("start_ea", block_min.getOffset());
                block.addProperty("end_ea", block_min.getOffset());
                JsonArray succs_json = new JsonArray();
                CodeBlockReferenceIterator succs = null;
                try {
                    succs = cb.getDestinations(TaskMonitor.DUMMY);
                } catch (CancelledException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                try {
                    while (succs.hasNext()) {
                        CodeBlockReference s = succs.next();
                        succs_json.add(s.getDestinationAddress().getOffset());
                    }
                } catch (CancelledException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                block.add("succs", succs_json);
                funblocks.add(block);
            }
            function.add("blocks", funblocks);
            String fun_addr = String.valueOf(min.getOffset());
            theblocks.add(fun_addr, function);
        }
        gson.toJson(theblocks, jsonWriter);
        try {
            jsonWriter.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Msg.debug(this, "Json of basic blocks written to " + outpath);
    }

    protected void colorBlocks() {
        // doThreads();
        Color new_hit_color = new Color(0x00ff00);
        Color old_hit_color = new Color(0x00ffcc);
        Color not_hit_color = new Color(0x00ffff);
        Color pre_hit_color = new Color(0xccff00);

        ColorizingService colorizingService = tool.getService(ColorizingService.class);
        String ida_data = System.getenv("RESIM_IDA_DATA");
        if (ida_data == null) {
            Msg.error(this, "RESIM_IDA_DATA not defined");
            return;
        }
        String full = program.getExecutablePath();
        String resim_image = System.getenv("RESIM_IMAGE");
        if(!full.startsWith(resim_image)){
            Msg.error(this,  "executable does not start with resim_image");
        }
        String less_image = full.substring(resim_image.length());
        Msg.debug(this, "full executable path is "+full);
        Msg.debug(this, "less_image is "+less_image);
        //String hitspath = ida_data + File.separator + program.getName() + File.separator + program.getName();
        String hitspath = ida_data + File.separator + less_image;
        String latest_hits_file = hitspath + ".hits";
        String afl_hits_file = hitspath + "_afl.hits";
        File latest_f = new File(latest_hits_file);
        File afl_f = new File(afl_hits_file);
        Object latest_json = null;
        if(latest_f.isFile()){
            latest_json = Json.getJsonFromFile(latest_hits_file);
            if (latest_json == null) {
                Msg.error(this, "color blocks failed to get json from " + latest_hits_file);
                return;
            }
        }else if(afl_f.isFile()){
            latest_json = Json.getJsonFromFile(afl_hits_file);
            if (latest_json == null) {
                Msg.error(this, "color blocks failed to get json from " + latest_hits_file);
                return;
            }
        }
        ArrayList<Long> new_bb_list = (ArrayList<Long>) latest_json;
        //Object all_hits_json = Json.getJsonFromFile(all_hits_file);
        ArrayList<Long> all_bb_list = null;
        //if (all_hits_json != null) {
        //    all_bb_list = (ArrayList<Long>) all_hits_json;
        //} else {
        all_bb_list = new ArrayList<Long>();
        //}
        //ArrayList<Long> pre_bb_list = null;
        //Object pre_hits_json = Json.getJsonFromFile(all_hits_file);
        //if (pre_hits_json != null) {
        //    pre_bb_list = (ArrayList<Long>) pre_hits_json;
        //} else {
        //    pre_bb_list = new ArrayList<Long>();
        //}

        BasicBlockModel bbm = new BasicBlockModel(program);
        int id = program.startTransaction("Test - Color Change");
        CodeBlock cb = null;
        Long adjusted_bb;
        try {
            for (Long bb : new_bb_list) {
                adjusted_bb = bb + this.load_offset;
                try {
                    cb = bbm.getCodeBlockAt(addr(adjusted_bb), TaskMonitor.DUMMY);
                } catch (CancelledException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                    Msg.error(this, "color blocks cancled exception " + e.toString());
                    return;
                }
                Color hit_color = old_hit_color;
                if (all_bb_list == null | !all_bb_list.contains(bb)) {
                    hit_color = new_hit_color;
                }
                colorizingService.setBackgroundColor(cb.getMinAddress(), cb.getMaxAddress(), hit_color);
            }
            for (Long bb : all_bb_list) {
                if (new_bb_list.contains((bb))) {
                    continue;
                }
                try {
                    cb = bbm.getCodeBlockAt(addr(bb), TaskMonitor.DUMMY);
                } catch (CancelledException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                    Msg.error(this, "color blocks cancled exception " + e.toString());
                    return;
                }
                colorizingService.setBackgroundColor(cb.getMinAddress(), cb.getMaxAddress(), not_hit_color);
            }
            for (Long bb : all_bb_list) {
                if (new_bb_list.contains(bb) || all_bb_list.contains(bb)) {
                    continue;
                }
                try {
                    cb = bbm.getCodeBlockAt(addr(bb), TaskMonitor.DUMMY);
                } catch (CancelledException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                    Msg.error(this, "color blocks cancled exception " + e.toString());
                    return;
                }
                colorizingService.setBackgroundColor(cb.getMinAddress(), cb.getMaxAddress(), pre_hit_color);
            }
        } finally {
            program.endTransaction(id, true);
        }

        program.flushEvents();
        // waitForBusyTool(tool);
    }

    protected void fooBar() {

        // doThreads();

    }

    protected void about() {
        JOptionPane.showMessageDialog(plugin.getTool().getActiveWindow(), "RESim plugins version 0.5", "RESim version",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void runToSyscall() {
        String syscall = JOptionPane.showInputDialog(null, "Syscall number (-1 for any)", "-1");
        if (syscall == null) {
            Msg.debug(this, "runToSyscall canceled");
        } else {
            String cmd = null;
            if (syscall.equals("-1")) {
                cmd = "runToSyscall()";
            } else {
                cmd = "runToSyscall(" + syscall + ")";
            }
            doRESimRefresh(cmd);
        }
    }

    void revStep(boolean into) {
        if (into) {
            doRESimRefresh("revStepInto()");
        } else {
            doRESimRefresh("revStepOver()");
        }
    }
    public Address addr(PluginTool tool, long offset) {
        AddressSpace dynRam = current_trace.getBaseAddressFactory().getDefaultAddressSpace();
        return dynRam.getAddress(offset);
    }
    public Address getMemReference(OperandFieldLocation loc, Instruction instruction) {
        Address retval = null;
        int opIndex = loc.getOperandIndex();
        Object[] operands = instruction.getOpObjects(opIndex);
        Msg.debug(this,  "getMemReference opIndex is "+opIndex+" len of operands "+operands.length);
        if (operands.length == 0) {
            //return operands[0];
            Msg.debug(this,  "op len is 0");
            return null;
        }
        
        InstructionPrototype prototype = instruction.getPrototype();
        List<Object> list =
            prototype.getOpRepresentationList(opIndex, instruction.getInstructionContext());
        if (list == null) {
            Msg.debug(this,  "list null");
            return null;
        }
        int sign = 1;
        long sum = 0;
        boolean in_brackets = false;
        boolean found_brackets = false;
        boolean domul = false;
        long preval = 0;
        for(Object o : list){          
            Msg.debug(this, "getMemReference preval "+preval+" sum "+sum);
            if(!in_brackets){
                if(o instanceof Character){
                    if((Character) o == '['){
                        in_brackets = true;
                    }
                }
            }else{
                if(o instanceof Character){
                    if((Character) o == '+'){
                        sum = sum + preval*sign;
                        sign = 1;
                    }else if ((Character) o == '-'){
                        sum = sum + preval*sign;
                        sign = -1;
                    }else if ((Character) o == '*'){
                        domul = true;
                        //Msg.debug(src, "setting multiply preval was "+preval);
                    }else if ((Character) o == ']'){
                        Msg.debug(this, "got end bracket preval was "+preval);
                        sum = sum + preval*sign;
                        found_brackets = true;
                        break;
                    }
                    Msg.debug(this, "getMemReference is character "+o+" sum now "+sum);
                }else if(o instanceof Register){
                    Register r = (Register) o;
                    //RegisterRow row = registerProvider.getRegisterRow(r);
                    //BigInteger regval = row.getValue();
                    preval = getRegValue(r.getName());
                    Msg.debug(this, "getMemReference o is register "+r+" got value "+preval);
                }else if(o instanceof Scalar){
                    Scalar s = (Scalar) o;
                    Msg.debug(this, "o is Scalar "+s);
                    if(domul){
                        preval = preval * s.getSignedValue();
                        domul = false;
                        //Msg.debug(src, "did mul, preval now "+preval);
                    }else{
                        sum = preval;
                        preval = s.getSignedValue();
                    }
                }else if(o instanceof GenericAddress){
                    GenericAddress a = (GenericAddress) o;
                    preval = a.getOffset();
                    Msg.debug(this, "generic address value "+preval);
                }
            }
        }
        if(found_brackets){
            retval = addr(tool, sum);
        }
         
        return retval;

    }
    void getLoadOffset(){
        
        String cmd = "getLoadSize('"+program.getName()+"')";
        doRESim(cmd).thenApply(return_string ->{
            if(return_string == null) {
                Msg.error(this, "Failed to get watchMarks json from RESim");
                return null;
            }
            Msg.debug(this, "return_string is"+return_string);
            long[] values = Arrays.stream(return_string.replaceAll("[^0-9,]", "").split(","))
                       .map(String::trim)
                       .mapToLong(Long::parseLong)
                       .toArray();
            this.load_offset = values[0];
            this.load_size = values[1];
            Msg.debug(this, "set load_offset to "+Long.toHexString(this.load_offset));

            return return_string;
        });
    }
}
