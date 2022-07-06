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

import java.awt.BorderLayout;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.function.*;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.ToolBarData;
import docking.action.builder.ActionBuilder;
import docking.widgets.table.DefaultEnumeratedColumnTableModel;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.*;
import ghidra.app.script.GhidraScript;

import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.framework.plugintool.PluginTool;

import resim.utils.RESimUtilsPlugin;
import resim.utils.RESimCursorAction;
import resim.utils.Json;
import resim.utils.RESimProvider;
import resim.utils.RESimRegAction;
import resim.utils.RESimResources.*;
import resim.utils.RESimResources;
public class RESimBookMarksProvider extends ComponentProviderAdapter implements RESimProvider{

    protected enum BookMarksTableColumns
        implements EnumeratedTableColumn<BookMarksTableColumns, RESimBookMarksRow> {
        INDEX("Index", Integer.class, RESimBookMarksRow::getIndex),
        PC("PC", Address.class, RESimBookMarksRow::getProgramCounter),
        CYCLE("cycle", Long.class, RESimBookMarksRow::getCycle),
        Mark("Mark", String.class, RESimBookMarksRow::getMark),
        MSG("Message", String.class, RESimBookMarksRow::getMsg),
        INSTRUCT("Instruction", String.class, RESimBookMarksRow::getInstruct),
        FUNCTION("Function", String.class, RESimBookMarksRow::getFunction),
        PID("pid", Long.class, RESimBookMarksRow::getPid);

        private final String header;
        private final Function<RESimBookMarksRow, ?> getter;
        private final BiConsumer<RESimBookMarksRow, Object> setter;
        private final Predicate<RESimBookMarksRow> editable;
        private final Class<?> cls;

        @SuppressWarnings("unchecked")
        <T> BookMarksTableColumns(String header, Class<T> cls, Function<RESimBookMarksRow, T> getter,
                BiConsumer<RESimBookMarksRow, T> setter, Predicate<RESimBookMarksRow> editable) {
            this.header = header;
            this.cls = cls;
            this.getter = getter;
            this.setter = (BiConsumer<RESimBookMarksRow, Object>) setter;
            this.editable = editable;
        }

        <T> BookMarksTableColumns(String header, Class<T> cls, Function<RESimBookMarksRow, T> getter) {
            this(header, cls, getter, null, null);
        }

        @Override
        public Class<?> getValueClass() {
            return cls;
        }

        @Override
        public Object getValueOf(RESimBookMarksRow row) {
            return getter.apply(row);
        }

        @Override
        public void setValueOf(RESimBookMarksRow row, Object value) {
            setter.accept(row, value);
        }

        @Override
        public String getHeader() {
            return header;
        }

        @Override
        public boolean isEditable(RESimBookMarksRow row) {
            return setter != null && editable.test(row);
        }
    }

    protected static class BookMarksTableModel
            extends DefaultEnumeratedColumnTableModel<BookMarksTableColumns, RESimBookMarksRow> {

        public BookMarksTableModel() {
            super("BookMarks", BookMarksTableColumns.class);
        }

        @Override
        public List<BookMarksTableColumns> defaultSortOrder() {
            return List.of(BookMarksTableColumns.INDEX);
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
    protected class AddAction extends AbstractAddAction {
        public static final String GROUP = DebuggerResources.GROUP_CONTROL;

        public AddAction() {
            super(plugin);
            setToolBarData(new ToolBarData(ICON, GROUP, "4"));
            addLocalAction(this);
            setEnabled(false);
        }

        @Override
        public void actionPerformed(ActionContext context) {
            String bookmark = JOptionPane.showInputDialog("Bookmark Name?");
            String cmd = "setDebugBookmark('"+bookmark+"')";
            Msg.debug(this,  "Add bookmark is "+cmd);
            resimUtils.doRESim(cmd).thenApply(stuff ->{
                Msg.debug(this,  "resim said "+stuff);
                resimUtils.addMessage(stuff);
                refresh();
                return stuff;
            });
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


    protected final BookMarksTableModel bookMarksTableModel = new BookMarksTableModel();
    protected GhidraTable bookMarksTable;
    protected GhidraTableFilterPanel<RESimBookMarksRow> bookMarkFilterPanel;

    private JPanel mainPanel = new JPanel(new BorderLayout());

    private RESimBookMarkActionContext myActionContext;
    private RESimUtilsPlugin resimUtils; 
    private RESimBookMarksPlugin plugin;
    private RefreshAction actionRefresh;
    private AddAction actionAdd;

    public RESimBookMarksProvider(RESimBookMarksPlugin plugin)  {
        super(plugin.getTool(), "BookMarks", plugin.getName());
        this.plugin = plugin;
        PluginTool tool = plugin.getTool();

        
        this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

        setTitle("BOOK MARKS");
        setIcon(RESimResources.ICON_RETOP);
        setHelpLocation(DebuggerResources.HELP_PROVIDER_STACK);
        setWindowMenuGroup(DebuggerPluginPackage.NAME);
        Msg.debug(this,  "did set window");
        buildMainPanel();

        setDefaultWindowPosition(WindowPosition.BOTTOM);

        setVisible(true);
        contextChanged();
        resimUtils = RESimUtilsPlugin.getRESimUtils(tool);
        if(resimUtils == null){
            Msg.error(this, "Failed to get RESimUtils.");
            return;
        }
        createActions();
        resimUtils.registerInit(this);
    }

    protected void buildMainPanel() {
        bookMarksTable = new GhidraTable(bookMarksTableModel);
        mainPanel.add(new JScrollPane(bookMarksTable));
        bookMarkFilterPanel = new GhidraTableFilterPanel<>(bookMarksTable, bookMarksTableModel);
        mainPanel.add(bookMarkFilterPanel, BorderLayout.SOUTH);

        bookMarksTable.getSelectionModel().addListSelectionListener(evt -> {
            if (evt.getValueIsAdjusting()) {
                return;
            }
            contextChanged();
        });

        bookMarksTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getButton() == MouseEvent.BUTTON2) {
                    Msg.info(this,  "right click");
                }
                if (e.getClickCount() < 2 || e.getButton() != MouseEvent.BUTTON1) {
                    return;
                }
                if (listingService == null) {
                    return;
                }
                if (myActionContext == null) {
                    return;
                }
                int index = myActionContext.getRow().getIndex();
                String cmd = "goToDebugBookmark("+index+")";
                resimUtils.doRESimRefresh(cmd);

            }

            @Override
            public void mouseReleased(MouseEvent e) {
                int selectedRow = bookMarksTable.getSelectedRow();
                RESimBookMarksRow row = bookMarksTableModel.getRowObject(selectedRow);
                rowActivated(row);
            }

            private void rowActivated(RESimBookMarksRow row) {
                // TODO Auto-generated method stub
                
            }
        });

        // TODO: Adjust default column widths?
        TableColumnModel columnModel = bookMarksTable.getColumnModel();

        TableColumn levelCol = columnModel.getColumn(BookMarksTableColumns.INDEX.ordinal());
        levelCol.setPreferredWidth(25);

    }

    @Override
    public void contextChanged() {
        RESimBookMarksRow row = bookMarkFilterPanel.getSelectedItem();
        myActionContext =
            row == null ? null : new RESimBookMarkActionContext(this, row, bookMarksTable);
        super.contextChanged();
    }

    protected void createActions() {
        new ActionBuilder("Refresh book marks", getName())
            .menuPath(RESimUtilsPlugin.MENU_RESIM, "Refresh", "&Book Marks")
            .menuGroup(RESimUtilsPlugin.MENU_RESIM, "Refresh")
            .onAction(c -> refresh())
            .buildAndInstall(tool);
        actionRefresh = new RefreshAction();
        actionAdd = new AddAction();

        /* Do this here so the bookmarks get refreshed */
        RESimCursorAction revTrackAddrAction = new RESimCursorAction("Rev track address", "revTaintAddr", resimUtils, this, false);
        tool.addAction(revTrackAddrAction);
        RESimRegAction revTrackRegAction = new RESimRegAction("Rev track register", "revTaintReg", resimUtils, this, true);
        tool.addAction(revTrackRegAction);
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
        bookMarksTableModel.clear();
    }
    public void add(RESimBookMarksRow row) {
        bookMarksTableModel.add(row);
    }

    public void add(HashMap<Object, Object> entry, int index){
        String mark = (String) entry.get("mark");
        String msg = (String) entry.get("msg");
        String instruct = (String) entry.get("instruct");
        String fun = (String) entry.get("fun");
        long ip = (long) entry.get("ip");
        Address ip_addr = resimUtils.addr(ip);
        long cycle = (long) entry.get("rel_cycle");
        long pid = (long) entry.get("pid");
 //     public RESimBookMarksRow(RESimBookMarksProvider provider, int index, String mark, Address pc, long cycle, long pid, String instruct, String msg) {

         RESimBookMarksRow wmr = new RESimBookMarksRow(this, index, mark, ip_addr, cycle, pid, instruct, fun, msg);
         add(wmr); 
    }
    @SuppressWarnings("unchecked")
    public void refresh(){
        Msg.debug(this, "refresh bookmarks");
        if(resimUtils == null) {
            Msg.debug(this,"call to get RESimUtils");
            System.out.println("call to getRESimUtils");
            resimUtils = RESimUtilsPlugin.getRESimUtils(tool);
        }
        if(resimUtils == null) {
            Msg.error(this,  "Cannot refresh, no RESimUtils");
            return;
        }

        clear();
        String cmd = "getBookmarksJson()";
        Msg.debug(this,  "refresh about to call resimUtils");
        resimUtils.doRESim(cmd).thenApply(book_string -> {
            if(book_string == null) {
                Msg.error(this, "Failed to get bookMarks json from RESim");
                return null;
            }
            Msg.debug(this, "bookmark json:"+book_string);
            Object watch_json = Json.getJson(book_string);
            java.util.List<Object> bookMarks = (java.util.ArrayList<Object>) watch_json;
            int index = 1;
            for(Object o : bookMarks){
                HashMap<Object, Object> entry = (HashMap<Object, Object>) o;
                add(entry, index);
                index++;
            }
            actionRefresh.setEnabled(true);
            actionAdd.setEnabled(true);
            actionRefresh.setEnabled(true);
            return book_string;
        });

    }
    
}
