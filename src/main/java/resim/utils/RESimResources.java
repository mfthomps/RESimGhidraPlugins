package resim.utils;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import docking.action.DockingAction;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.HelpLocation;
import resources.ResourceManager;
/*
 * RESim resources, e.g., for associating actions with icons on plugin panels
 */
public interface RESimResources {
    ImageIcon ICON_REFRESH = ResourceManager.loadImage("images/view-refresh.png");
    ImageIcon ICON_ADD = ResourceManager.loadImage("images/add.png");
    ImageIcon ICON_RETOP = ResourceManager.loadImage("images/retop.png");
    ImageIcon ICON_RESTEPINTO = ResourceManager.loadImage("images/revstepinto.png");
    ImageIcon ICON_RESTEPOVER = ResourceManager.loadImage("images/revstepover.png");

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
    abstract class AbstractRevStepIntoAction extends DockingAction {
        public static final String NAME = "Reverse step into";
        public static final Icon ICON = ICON_RESTEPINTO;
        public static final String HELP_ANCHOR = "revstep";

        public AbstractRevStepIntoAction(Plugin owner) {
            super(NAME, owner.getName());
            setDescription("Reverse step into");
            setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
        }
    } 
    abstract class AbstractRevStepOverAction extends DockingAction {
        public static final String NAME = "Reverse step over";
        public static final Icon ICON = ICON_RESTEPOVER;
        public static final String HELP_ANCHOR = "revstep";

        public AbstractRevStepOverAction(Plugin owner) {
            super(NAME, owner.getName());
            setDescription("Reverse step over");
            setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
        }
    } 
}
