# Ghidra Debugger plugin for RESim
A set of plugins for the Ghidra Debugger to allow Ghidra to be used as the
disassember/debugger with the RESim reverse engineering platform.
See https://github.com/mfthomps/RESim

These plugins currently require Ghidra version 10.2\_DEV, which can be rebuilt
from the Ghidra repo per their rebuilding instructions.  After rebuilding,
unzip the install zip into a directory and set GHIDRA\_INSTALL\_DIR to that.

Set the GHIDRA\_DEV\_DIR environment variable if you wish to optionally run from
the ghidra repo directory, e.g., test modifications without reinstalling extensions.

Run the ./buildRESimExtension.sh script to build and install the extension.
After starting Ghidra from GHIDRA\_INSTALL\_DIR, use the File / Install Extensions
and click the Add icon (upper right).  Then navigate to and select:

  GHIDRA\_INSTALL\_DIR/Extensions/RESimGhidraPlugins

Your must then restart Ghidra.

When the debugger is started, a number of RESim windows will appear.  Drag those to tabbed windows 
per taste.
