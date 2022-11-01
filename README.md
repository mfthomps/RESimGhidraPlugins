# Ghidra Debugger plugin for RESim
These are a set of plugins for the Ghidra Debugger to allow Ghidra to be used as the
disassembler/debugger with the RESim reverse engineering platform.
See https://github.com/mfthomps/RESim

**NOTE:** This is preliminary work.  While many of the RESim IDA Pro plugin features 
are replicated here, it is not complete and not fully tested.

## Install Ghidra from its repo
These plugins currently require Ghidra version 10.3, which can be rebuilt
from the Ghidra repo (https://github.com/NationalSecurityAgency/ghidra) per their rebuilding instructions.  
The released version of Ghidra (10.1.4) will not work, it is missing some necessary functions.
After rebuilding ghidra, find its installation zip in ghidra/build/dist.
Unzip the install zip into a directory and set an GHIDRA\_INSTALL\_DIR environment variable to that,
and set it in your .bashrc.

Assuming you've performed the installation step, keep the Ghidra repo up to date using the 
rebuildGhidra.sh script in the RESimGhidraPlugins repo described below.

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
GHIDRA\_INSTALL\_DIR/Extensions directory.

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

## Ghidra Debugger hover plugins
The hover plugins included herein are largely separable from other plugs.  They display register and address values
when the mouse hovers over operands.

## Development
If you are developing the plugin with Eclipse, you can test the plugin within the Ghidra repo environment
by creating a link from the repo's Ghidra/Extensions to the RESimGhidraPlugins repo.  This lets you test using class files
instead of the jar's, and does not require reinstalling the plugin and restarting Ghidra.
