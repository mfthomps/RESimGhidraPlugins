# Ghidra Debugger plugin for RESim
These are a set of plugins for the Ghidra Debugger to allow Ghidra to be used as the
disassembler/debugger with the RESim reverse engineering platform.
See https://github.com/mfthomps/RESim

**NOTE:** This is ongoing work.  While most of the RESim IDA Pro plugin features 
are replicated here, it is an ongoing development.

## Install Ghidra from its repo
These plugins have been tested with Ghidra release 12.0.4.
Get that Release from \url{https://github.com/NationalSecurityAgency/ghidra}.
Install per the Install section in that README.

## Install gdb-multiarch
The computer that runs Ghidra should have the the following installed:
* gdb-multiarch 
* pthon3-pip.
* sudo python3 -m pip install --break-system-packages --force-reinstall 'protobuf>=6.31.0'

Edit your ~/.config/gdb/gdbinit file to include
* set auto-solib-add 0
* set sysroot [path to your local target root file system, i.e., the RESim application root]

For now, the sysroot must be changed with each different application root.  The Ghidra gdb invocation
dialog does not permit command line arguments.

## Get the RESim plugin
The plugin can be installed using the github release at
get the zip from box.com.
Download that zip file.

## Install the RESim plugin into Ghidra
After starting Ghidra use menu File / Install Extensions
and click the Add icon (upper right).  Then navigate to and select the ...RESimPlugin.zip file
that you got from github.

Your must then restart Ghidra.

When the debugger is started, you should see a "RESim" menu bar item, if not then the plugin did not install properly.
Try using File / Configure and then click the plugin icon in the upper right.  
In the resulting dialog scroll down to the plugins having a "RESIM" prefix and make sure they are selected.  

Add the RESim windows to the GUI using the Window / Debugger menu to select the RESim windows (the ones with the 
spinning top icon).  Drag those to tabbed windows per taste using the blue bar, not the title bar. 

## Connect to Simics
Use the Debugger / Configure and Launch... / "gdb remote" to view the dialog.  Populate it with the path to your
target image, the hostname of where Simics is running and port 9123.  Use the "remote" as the target value.

## Development
The Ghidra Dev Eclipse plugin is used for development.  Use that to create a new module (importing works, but then fails on 
exporting of the plugin.)  Then manually create a symlink from the eclipse workspace project src/main/java/resim to
the RESimGhidraPlugins/sr/main/java/resim.  Do the same for the src/main/resources/images/re* files. 
