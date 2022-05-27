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
package resim.watchmarks;

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
import docking.action.builder.ActionBuilder;
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
import ghidra.program.model.listing.Program;
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
import utilities.util.SuppressableCallback;
import utilities.util.SuppressableCallback.Suppression;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import ghidra.framework.plugintool.PluginTool;

import resim.utils.DebuggerRESimUtilsPlugin;
import resim.utils.Json;
import resim.utils.RESimProvider;
public class DebuggerWatchMarksProvider extends ComponentProviderAdapter implements RESimProvider{

	protected enum WatchMarksTableColumns
		implements EnumeratedTableColumn<WatchMarksTableColumns, WatchMarksRow> {
		INDEX("Index", Integer.class, WatchMarksRow::getIndex),
		PC("PC", Address.class, WatchMarksRow::getProgramCounter),
	    CYCLE("cycle", Long.class, WatchMarksRow::getCycle),
		MSG("Message", String.class, WatchMarksRow::getMsg),
	    PID("pid", Long.class, WatchMarksRow::getPid);

		private final String header;
		private final Function<WatchMarksRow, ?> getter;
		private final BiConsumer<WatchMarksRow, Object> setter;
		private final Predicate<WatchMarksRow> editable;
		private final Class<?> cls;

		@SuppressWarnings("unchecked")
		<T> WatchMarksTableColumns(String header, Class<T> cls, Function<WatchMarksRow, T> getter,
				BiConsumer<WatchMarksRow, T> setter, Predicate<WatchMarksRow> editable) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<WatchMarksRow, Object>) setter;
			this.editable = editable;
		}

		<T> WatchMarksTableColumns(String header, Class<T> cls, Function<WatchMarksRow, T> getter) {
			this(header, cls, getter, null, null);
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(WatchMarksRow row) {
			return getter.apply(row);
		}

		@Override
		public void setValueOf(WatchMarksRow row, Object value) {
			setter.accept(row, value);
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public boolean isEditable(WatchMarksRow row) {
			return setter != null && editable.test(row);
		}
	}

	protected static class WatchMarksTableModel
			extends DefaultEnumeratedColumnTableModel<WatchMarksTableColumns, WatchMarksRow> {

		public WatchMarksTableModel() {
			super("WatchMarks", WatchMarksTableColumns.class);
		}

		@Override
		public List<WatchMarksTableColumns> defaultSortOrder() {
			return List.of(WatchMarksTableColumns.INDEX);
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


	protected final WatchMarksTableModel watchMarksTableModel = new WatchMarksTableModel();
	protected GhidraTable watchMarksTable;
	protected GhidraTableFilterPanel<WatchMarksRow> watchMarkFilterPanel;

	private JPanel mainPanel = new JPanel(new BorderLayout());

	private DebuggerWatchMarkActionContext myActionContext;
	private DebuggerRESimUtilsPlugin resimUtils; 

	public DebuggerWatchMarksProvider(DebuggerWatchMarksPlugin plugin)  {
		super(plugin.getTool(), "WatchMarks", plugin.getName());
		//this.plugin = plugin;
	    PluginTool tool = plugin.getTool();

		
		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		setTitle("WATCH MARKS");
		setIcon(DebuggerResources.ICON_PROVIDER_STACK);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_STACK);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);
        Msg.debug(this,  "did set window");
		buildMainPanel();

		setDefaultWindowPosition(WindowPosition.BOTTOM);
		createActions();

		setVisible(true);
		contextChanged();
	}

	protected void buildMainPanel() {
		watchMarksTable = new GhidraTable(watchMarksTableModel);
		mainPanel.add(new JScrollPane(watchMarksTable));
		watchMarkFilterPanel = new GhidraTableFilterPanel<>(watchMarksTable, watchMarksTableModel);
		mainPanel.add(watchMarkFilterPanel, BorderLayout.SOUTH);

		watchMarksTable.getSelectionModel().addListSelectionListener(evt -> {
			if (evt.getValueIsAdjusting()) {
				return;
			}
			contextChanged();
		});

		watchMarksTable.addMouseListener(new MouseAdapter() {
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
				String cmd = "goToDataMark("+index+")";
				try {
					String result = resimUtils.doRESimRefresh(cmd);
				}catch(Exception error) {
					error.printStackTrace();
				}

			}

			@Override
			public void mouseReleased(MouseEvent e) {
				int selectedRow = watchMarksTable.getSelectedRow();
				WatchMarksRow row = watchMarksTableModel.getRowObject(selectedRow);
				rowActivated(row);
			}

			private void rowActivated(WatchMarksRow row) {
				// TODO Auto-generated method stub
				
			}
		});

		// TODO: Adjust default column widths?
		TableColumnModel columnModel = watchMarksTable.getColumnModel();

		TableColumn levelCol = columnModel.getColumn(WatchMarksTableColumns.INDEX.ordinal());
		levelCol.setPreferredWidth(25);
		TableColumn baseCol = columnModel.getColumn(WatchMarksTableColumns.PC.ordinal());
		baseCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
	}

	@Override
	public void contextChanged() {
		WatchMarksRow row = watchMarkFilterPanel.getSelectedItem();
		myActionContext =
			row == null ? null : new DebuggerWatchMarkActionContext(this, row, watchMarksTable);
		super.contextChanged();
	}



	protected void createActions() {
    	new ActionBuilder("Refresh watch marks", getName())
			.menuPath(DebuggerRESimUtilsPlugin.MENU_RESIM, "Refresh", "&Watch Marks")
			.menuGroup(DebuggerRESimUtilsPlugin.MENU_RESIM, "Refresh")
			.onAction(c -> refresh())
			.buildAndInstall(tool);
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
		setSubTitle(computeSubTitle());
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
		watchMarksTableModel.clear();
	}
	public void add(WatchMarksRow row) {
		watchMarksTableModel.add(row);
	}
        public void add(HashMap<Object, Object> entry, int index){
        	String msg = (String) entry.get("msg");
            long ip = (long) entry.get("ip");
            Address ip_addr = resimUtils.addr(ip);
            long cycle = (long) entry.get("cycle");
            long pid = (long) entry.get("pid");
             WatchMarksRow wmr = new WatchMarksRow(this, index, msg, ip_addr, cycle, pid);
             add(wmr); 
        }
	@SuppressWarnings("unchecked")
	public void refresh(){
		Msg.debug(this, "refresh watchmarks");
		if(resimUtils == null) {
			Msg.out("call to get RESimUtils");
			System.out.println("call to getRESimUtils");
			resimUtils = DebuggerRESimUtilsPlugin.getRESimUtils(tool);
		}
		if(resimUtils == null) {
			Msg.error(this,  "Cannot refresh, no RESimUtils");
			return;
		}

		clear();
        String cmd = "getWatchMarks()";
        //println("cmd is "+cmd);

        String watchString = resimUtils.doRESim(cmd);
        if(watchString == null) {
        	Msg.error(this, "Failed to get watchMarks json from RESim");
        }

        Object watch_json = Json.getJson(watchString);
        java.util.List<Object> watchMarks = (java.util.ArrayList<Object>) watch_json;
        int index = 0;
        for(Object o : watchMarks){
            HashMap<Object, Object> entry = (HashMap<Object, Object>) o;
            add(entry, index);
            index++;
        }
	}
	
}
