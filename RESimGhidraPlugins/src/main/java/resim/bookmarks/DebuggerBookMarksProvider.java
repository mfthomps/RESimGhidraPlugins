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
import resim.watchmarks.WatchMarksRow;
public class DebuggerBookMarksProvider extends ComponentProviderAdapter implements RESimProvider{

	protected enum BookMarksTableColumns
		implements EnumeratedTableColumn<BookMarksTableColumns, BookMarksRow> {
		INDEX("Index", Integer.class, BookMarksRow::getIndex),
		MSG("Message", String.class, BookMarksRow::getMsg);

		private final String header;
		private final Function<BookMarksRow, ?> getter;
		private final BiConsumer<BookMarksRow, Object> setter;
		private final Predicate<BookMarksRow> editable;
		private final Class<?> cls;

		@SuppressWarnings("unchecked")
		<T> BookMarksTableColumns(String header, Class<T> cls, Function<BookMarksRow, T> getter,
				BiConsumer<BookMarksRow, T> setter, Predicate<BookMarksRow> editable) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<BookMarksRow, Object>) setter;
			this.editable = editable;
		}

		<T> BookMarksTableColumns(String header, Class<T> cls, Function<BookMarksRow, T> getter) {
			this(header, cls, getter, null, null);
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(BookMarksRow row) {
			return getter.apply(row);
		}

		@Override
		public void setValueOf(BookMarksRow row, Object value) {
			setter.accept(row, value);
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public boolean isEditable(BookMarksRow row) {
			return setter != null && editable.test(row);
		}
	}

	protected static class BookMarksTableModel
			extends DefaultEnumeratedColumnTableModel<BookMarksTableColumns, BookMarksRow> {

		public BookMarksTableModel() {
			super("BookMarks", BookMarksTableColumns.class);
		}

		@Override
		public List<BookMarksTableColumns> defaultSortOrder() {
			return List.of(BookMarksTableColumns.INDEX);
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
	protected GhidraTableFilterPanel<BookMarksRow> bookMarkFilterPanel;

	private JPanel mainPanel = new JPanel(new BorderLayout());

	private DebuggerBookMarkActionContext myActionContext;
	private DebuggerRESimUtilsPlugin resimUtils; 

	public DebuggerBookMarksProvider(DebuggerBookMarksPlugin plugin)  {
		super(plugin.getTool(), "BookMarks", plugin.getName());
		//this.plugin = plugin;
	    PluginTool tool = plugin.getTool();

		
		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		setTitle("BOOK MARKS");
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
				try {
					String result = resimUtils.doRESimRefresh(cmd);
				}catch(Exception error) {
					error.printStackTrace();
				}

			}

			@Override
			public void mouseReleased(MouseEvent e) {
				int selectedRow = bookMarksTable.getSelectedRow();
				BookMarksRow row = bookMarksTableModel.getRowObject(selectedRow);
				rowActivated(row);
			}

			private void rowActivated(BookMarksRow row) {
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
		BookMarksRow row = bookMarkFilterPanel.getSelectedItem();
		myActionContext =
			row == null ? null : new DebuggerBookMarkActionContext(this, row, bookMarksTable);
		super.contextChanged();
	}



	protected void createActions() {
    	new ActionBuilder("Refresh book marks", getName())
			.menuPath(DebuggerRESimUtilsPlugin.MENU_RESIM, "Refresh", "&Book Marks")
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
		bookMarksTableModel.clear();
	}
	public void add(BookMarksRow row) {
		bookMarksTableModel.add(row);
	}
    public void add(String msg, int index){

         BookMarksRow wmr = new BookMarksRow(this, index, msg);
         add(wmr); 
    }
	@SuppressWarnings("unchecked")
	public void refresh(){
		Msg.debug(this, "refresh bookmarks");
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
        String cmd = "listBookmarks()";
        //println("cmd is "+cmd);

        String bookString = resimUtils.doRESim(cmd);
        if(bookString == null) {
        	Msg.error(this, "Failed to get bookMarks json from RESim");
        }
        Msg.debug(this,"bookmark string: "+bookString);
        String[] lines = bookString.split("\r?\n|\r");
        int index = 0;
        String backtrack = "backtrack";
        String start = "START";
        for(String line : lines) {
        	if(line.contains(":")) {
            	index = index+1;
            	String[] parts = line.split(":");
            	String entry = parts[1].trim();
            	if(parts[1].startsWith(backtrack) &! entry.contains(start)) {
            		entry = "<<<"+entry.substring(backtrack.length());
            	}
        		add(entry, index);        		
        	}
        }

	}
	
}
