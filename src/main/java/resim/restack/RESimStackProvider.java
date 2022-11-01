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
package resim.restack;

import java.awt.BorderLayout;

import org.apache.commons.compress.utils.FileNameUtils;
import org.apache.commons.io.FilenameUtils;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.HashMap;
import java.util.function.*;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.action.ToolBarData;
import docking.action.builder.ActionBuilder;
import docking.ActionContext;
import docking.WindowPosition;
import docking.widgets.table.CustomToStringCellRenderer;
import docking.widgets.table.DefaultEnumeratedColumnTableModel;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.*;

import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;

import ghidra.trace.model.*;

import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import resim.utils.RESimUtilsPlugin;
import resim.utils.RESimResources;
import resim.utils.RESimResources.*;
import resim.utils.Json;
import resim.utils.RESimProvider;

public class RESimStackProvider extends ComponentProviderAdapter implements RESimProvider{

    protected enum REStackTableColumns
        implements EnumeratedTableColumn<REStackTableColumns, RESimStackRow> {
        INDEX("Index", Integer.class, RESimStackRow::getIndex),
        PC("PC", Address.class, RESimStackRow::getProgramCounter),
        INSTRUCT("Instruct", String.class, RESimStackRow::getInstruct),
        FUN("Function", String.class, RESimStackRow::getFun),
        FNAME("File", String.class, RESimStackRow::getFname);
        

        private final String header;
        private final Function<RESimStackRow, ?> getter;
        private final BiConsumer<RESimStackRow, Object> setter;
        private final Predicate<RESimStackRow> editable;
        private final Class<?> cls;

        @SuppressWarnings("unchecked")
        <T> REStackTableColumns(String header, Class<T> cls, Function<RESimStackRow, T> getter,
                BiConsumer<RESimStackRow, T> setter, Predicate<RESimStackRow> editable) {
            this.header = header;
            this.cls = cls;
            this.getter = getter;
            this.setter = (BiConsumer<RESimStackRow, Object>) setter;
            this.editable = editable;
        }

        <T> REStackTableColumns(String header, Class<T> cls, Function<RESimStackRow, T> getter) {
            this(header, cls, getter, null, null);
        }

        @Override
        public Class<?> getValueClass() {
            return cls;
        }

        @Override
        public Object getValueOf(RESimStackRow row) {
            return getter.apply(row);
        }

        @Override
        public void setValueOf(RESimStackRow row, Object value) {
            setter.accept(row, value);
        }

        @Override
        public String getHeader() {
            return header;
        }

        @Override
        public boolean isEditable(RESimStackRow row) {
            return setter != null && editable.test(row);
        }
    }

    protected static class REStackTableModel
            extends DefaultEnumeratedColumnTableModel<REStackTableColumns, RESimStackRow> {

        public REStackTableModel(PluginTool tool) {
            super(tool, "REStack", REStackTableColumns.class);
        }

        @Override
        public List<REStackTableColumns> defaultSortOrder() {
            return List.of(REStackTableColumns.INDEX);
        }
    }
    protected class RefreshAction extends AbstractRefreshAction {
        public static final String GROUP = DebuggerResources.GROUP_CONTROL;

        public RefreshAction() {
            super(plugin);
            setToolBarData(new ToolBarData(ICON, GROUP, "4"));
            addLocalAction(this);
            setEnabled(false);
        }

        @Override
        public void actionPerformed(ActionContext context) {
            refresh();
        }

        @Override
        public boolean isEnabledForContext(ActionContext context) {
            boolean retval = false;
            if(resimUtils != null) {
                retval = resimUtils.connected();
            }
            return retval;
        }
    }

    protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
        if (!Objects.equals(a.getTrace(), b.getTrace())) {
            return false;
        }
        if (!Objects.equals(a.getThread(), b.getThread())) {
            return false;
        }
        if (!Objects.equals(a.getTime(), b.getTime())) {
            return false;
        }
        if (!Objects.equals(a.getFrame(), b.getFrame())) {
            return false;
        }
        return true;
    }



    //private final DebuggerStackPlugin plugin;

    // Table rows access these for function name resolution
    DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;


    @AutoServiceConsumed
    private DebuggerTraceManagerService traceManager;
    // @AutoServiceConsumed  by method
    private DebuggerModelService modelService;
    // @AutoServiceConsumed via method
    DebuggerStaticMappingService mappingService;
    @AutoServiceConsumed
    private DebuggerListingService listingService; // TODO: Goto pc on double-click
    @AutoServiceConsumed
    private MarkerService markerService; // TODO: Mark non-current frame PCs, too. (separate plugin?)
    @SuppressWarnings("unused")
    private final AutoService.Wiring autoServiceWiring;


    protected final REStackTableModel reStackTableModel;
    protected GhidraTable reStackTable;
    protected GhidraTableFilterPanel<RESimStackRow> reStackFilterPanel;

    private JPanel mainPanel = new JPanel(new BorderLayout());

    private RESimStackActionContext myActionContext;
    private RESimUtilsPlugin resimUtils; 
    private RefreshAction actionRefresh;
    private RESimStackPlugin plugin;

    public RESimStackProvider(RESimStackPlugin plugin)  {
        super(plugin.getTool(), "REStack", plugin.getName());
        this.plugin = plugin;
        PluginTool tool = plugin.getTool();
        reStackTableModel = new REStackTableModel(tool);

        
        this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

        setTitle("REStack Trace");
        setIcon(RESimResources.ICON_RETOP);
        setHelpLocation(DebuggerResources.HELP_PROVIDER_STACK);
        setWindowMenuGroup(DebuggerPluginPackage.NAME);

        Msg.debug(this, "call buildMainPanel");
        buildMainPanel();

        setDefaultWindowPosition(WindowPosition.BOTTOM);
        Msg.debug(this, "call to create actions...");
        createActions();

        setVisible(true);
        contextChanged();
        

        Msg.debug(this, "call to get RESimUtils from REStack");
        resimUtils = RESimUtilsPlugin.getRESimUtils(tool);
        if(resimUtils == null) {
            Msg.error(this,  "Failed to get resimUtils");
        }else {
            resimUtils.registerRefresh(this);
            Msg.debug(this, "Registered refresh with resimUtils");
        }

    }

    protected void buildMainPanel() {
        reStackTable = new GhidraTable(reStackTableModel);
        mainPanel.add(new JScrollPane(reStackTable));
        reStackFilterPanel = new GhidraTableFilterPanel<>(reStackTable, reStackTableModel);
        mainPanel.add(reStackFilterPanel, BorderLayout.SOUTH);

        reStackTable.getSelectionModel().addListSelectionListener(evt -> {
            if (evt.getValueIsAdjusting()) {
                return;
            }
            contextChanged();
        });

        reStackTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() < 2 || e.getButton() != MouseEvent.BUTTON1) {
                    return;
                }
                if (listingService == null) {
                    return;
                }
                if (myActionContext == null) {
                    return;
                }
                
                Address pc = myActionContext.getRow().getProgramCounter();
                if (pc == null) {
                    return;
                }
                listingService.goTo(pc, true);
            }


            @Override
            public void mouseReleased(MouseEvent e) {
                int selectedRow = reStackTable.getSelectedRow();
                RESimStackRow row = reStackTableModel.getRowObject(selectedRow);
                rowActivated(row);
            }

            private void rowActivated(RESimStackRow row) {
                // TODO Auto-generated method stub
                
            }
        });

        // TODO: Adjust default column widths?
        TableColumnModel columnModel = reStackTable.getColumnModel();

        TableColumn levelCol = columnModel.getColumn(REStackTableColumns.INDEX.ordinal());
        levelCol.setPreferredWidth(25);
        TableColumn baseCol = columnModel.getColumn(REStackTableColumns.PC.ordinal());
        baseCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
    }

    @Override
    public void contextChanged() {
        RESimStackRow row = reStackFilterPanel.getSelectedItem();
        myActionContext =
            row == null ? null : new RESimStackActionContext(this, row, reStackTable);
        super.contextChanged();
    }

    protected void createActions() {
        Msg.debug(this, "createActions");
        new ActionBuilder("Refresh stack trace", getName())
            .menuPath(RESimUtilsPlugin.MENU_RESIM, "Refresh", "&Stack trace")
            .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Refresh")
            .onAction(c -> refresh())
            .buildAndInstall(tool);
        actionRefresh = new RefreshAction();
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    @Override
    public ActionContext getActionContext(MouseEvent event) {
        if (myActionContext == null) {
            return super.getActionContext(event);
        }
        return myActionContext;
    }

    protected String computeSubTitle() {
        TraceThread curThread = current.getThread();
        return curThread == null ? "" : curThread.getName();
    }

    protected void updateSubTitle() {
        //setSubTitle(computeSubTitle());
    }

    public void coordinatesActivated(DebuggerCoordinates coordinates) {
        if (sameCoordinates(current, coordinates)) {
            current = coordinates;
            return;
        }
        current = coordinates;

        updateSubTitle();
    }

    @AutoServiceConsumed
    public void setModelService(DebuggerModelService modelService) {
        this.modelService = modelService;
    }

    @AutoServiceConsumed
    private void setMappingService(DebuggerStaticMappingService mappingService) {

        this.mappingService = mappingService;

    }
    public void clear() {
        reStackTableModel.clear();
    }
    public void add(RESimStackRow row) {
        reStackTableModel.add(row);
    }
        public void add(HashMap<Object, Object> entry, int index){
            String instruct = (String) entry.get("instruct");
            Msg.debug(this, "adding instruct"+instruct);
            String fun = (String) entry.get("fun_of_ip");
            String fname = (String) entry.get("fname");
            String basename = FileNameUtils.getBaseName(fname);
            
            long ip = (long) entry.get("ip");
            Address ip_addr = resimUtils.addr(ip);
             RESimStackRow wmr = new RESimStackRow(this, index, instruct, fun, basename, ip_addr);
             add(wmr); 
        }
    @SuppressWarnings("unchecked")
    public void refresh(){
        Msg.info(this,  "refresh");
        if(resimUtils == null) {
            Msg.error(this,  "refresh failed, resimUtilsis null");
            return;
        }
        clear();
        String cmd = "getStackTrace()";
        Msg.info(this, "cmd is "+cmd);

        resimUtils.doRESim(cmd).thenApply(stack_string ->{
            Object stack_json = Json.getJson(stack_string);
            Msg.info(this, stack_string);
            java.util.List<Object> reStack = (java.util.ArrayList<Object>) stack_json;
            int index = 0;
            for(Object o : reStack){
                HashMap<Object, Object> entry = (HashMap<Object, Object>) o;
                add(entry, index);
                index++;
            }
            actionRefresh.setEnabled(true);
            return stack_string;
        });
    }
    
}
