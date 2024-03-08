# Ghidra Debugger plugin for RESim
These are a set of plugins for the Ghidra Debugger to allow Ghidra to be used as the
disassembler/debugger with the RESim reverse engineering platform.
See https://github.com/mfthomps/RESim

**NOTE:** This is preliminary work.  While most of the RESim IDA Pro plugin features 
are replicated here, it is not entirely complete and not fully tested.

## Install Ghidra from its repo
These plugins have been tested with Ghidra release 11.0.1.
Get that Release from \url{https://github.com/NationalSecurityAgency/ghidra}.
Unzip the release zip into a directory and set an GHIDRA\_INSTALL\_DIR environment variable to that,
and set it in your .bashrc.

NOTE: The Ghidra API's have changed and broken some of the UI refresh.  Thus, after selecting a new watch mar
or reversing execution, you must select the "Stack" item from the Ghidra debugger "Objects" pane and click the
refresh button.

## Install fork of gdb
Use of the Ghidra plugin requires a modified version of gdb, available at
\url{https://github.com/mfthomps/binutils-gdb}.  The modification causes
gdb to display responses from "monitor" commands using the same FD as used
for other gdb command results.  This is needed for Ghidra to see those results.
See the README in the forked gdb repo for information on building gdb.

## Get the RESim plugin
The plugin can be installed using the github release at
https://github.com/mfthomps/RESimGhidraPlugins/releases/latest
Download the RESimGhidraPlugins.tar and expand it into your 
GHIDRA\_INSTALL\_DIR/../Extensions directory. NOTE Ghidra has
two extensions directory.  Expand the plugin tar into the one
within the top level directory.

Alternately, clone the RESimGhidraPlugins repo 
run the ./buildRESimExtension.sh script to build and install the extension.

## Install the RESim plugin into Ghidra
After starting Ghidra from GHIDRA\_INSTALL\_DIR, use the menu: File / Install Extensions
and click the Add icon (upper right).  Then navigate to and select:

    GHIDRA_INSTALL_DIR/Extensions/RESimGhidraPlugins

Your must then restart Ghidra.

When the debugger is started, a number of RESim windows should appear.  Drag those to tabbed windows 
per taste. If RESim plugins don't seem to be present, use File / Configure and then click the 
plugin icon in the upper right.  In the resulting dialog scroll down to the plugins having
a "RESIM" prefix and make sure they are selected.  If the plugins are selected, but do not appear
in the windows, use the Window / Debugger menu to select the RESim windows (the ones with the top icon).

Use the RESim / Configure menu options to set the path to your customized gdb; the path to 
the file system root of the target binary, the host:port of your Simics host, and to set the ARM architecture if needed.
See the RESim-UsersGuide.pdf for additional information on using the Ghidra plugin with RESim.

## Ghidra Debugger hover plugin
The hover plugin included herein is largely separable from other plugs.  It displays reference addresses and values
when the mouse hovers over operands.   Ghidra now includes a native hover function for displaying register values.

## Development
To develop the plugin in Eclipse, you will need the GhidraDev Eclipse plugin.  See the Ghidra repo's README.  Once
that is installed in Eclipse, use GhidraDev / New / Ghidra Module Project to create a new project.  Uncheck all of the
Ghidra module templates.  After the project is created, right click on src/main/java and import the RESimGhidraPlugin
source from src/main/java/resim.  Use Import / General File System.  Be sure to click the "Advanced" button and direct
Eclipse to use links rather than copying files from the repo.
