# Ghidra Debugger plugin for RESim
A set of plugins for the Ghidra Debugger to allow Ghidra to be used as the
disassembler/debugger with the RESim reverse engineering platform.
See https://github.com/mfthomps/RESim

Use of the Ghidra plugin requires a modified version of gdb, available at
\url{https://github.com/mfthomps/binutils-gdb}.  The modification causes
gdb to display responses from "monitor" commands using the same FD as used
for other gdb command results.  This is needed for Ghidra to see those results.

These plugins currently require Ghidra version 10.2, which can be rebuilt
from the Ghidra repo per their rebuilding instructions.  After rebuilding,
unzip the install zip into a directory and set GHIDRA\_INSTALL\_DIR to that.

Run the ./buildRESimExtension.sh script to build and install the extension.
After starting Ghidra from GHIDRA\_INSTALL\_DIR, use the File / Install Extensions
and click the Add icon (upper right).  Then navigate to and select:

  GHIDRA\_INSTALL\_DIR/Extensions/RESimGhidraPlugins

Your must then restart Ghidra.

When the debugger is started, a number of RESim windows will appear.  Drag those to tabbed windows 
per taste.

Use the RESim / Configure menu options to set the path to your customized gdb; the path to 
the file system root of the target binary, the host:port of your Simics host, and to set the ARM architecture if needed.

If you are developing the plugin with Eclipse, you can test the plugin within the Ghidra repo environment
by creating a link from the repo's Ghidra/Extensions to the RESimGhidraPlugins repo.  This lets you test using class files
instead of the jar's, and does not require reinstalling the plugin and restarting Ghidra.
