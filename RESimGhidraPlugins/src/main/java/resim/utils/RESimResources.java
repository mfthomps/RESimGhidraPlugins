package resim.utils;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import docking.action.DockingAction;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public interface RESimResources {
	ImageIcon ICON_REFRESH = ResourceManager.loadImage("images/view-refresh.png");
	ImageIcon ICON_ADD = ResourceManager.loadImage("images/add.png");
	ImageIcon ICON_RETOP = ResourceManager.loadImage("images/retop.png");

	abstract class AbstractRefreshAction extends DockingAction {
		public static final String NAME = "Step Trace Snap Forward";
		public static final Icon ICON = ICON_REFRESH;
		public static final String HELP_ANCHOR = "refresh";

		public AbstractRefreshAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Refresh the data");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}	
	abstract class AbstractAddAction extends DockingAction {
		public static final String NAME = "Add";
		public static final Icon ICON = ICON_ADD;
		public static final String HELP_ANCHOR = "add";

		public AbstractAddAction(Plugin owner) {
			super(NAME, owner.getName());
			setDescription("Add item");
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}
	}
}
