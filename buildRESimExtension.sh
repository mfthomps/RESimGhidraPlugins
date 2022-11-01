#!/bin/bash
#
# Build the RESim Ghidra extension plugins and install them into the GHIDRA_INSTALL_DIR.
#
echo "GHIDRA_INSTALL_DIR is $GHIDRA_INSTALL_DIR" 
if [ -z $GHIDRA_INSTALL_DIR ]; then
    echo "Must define GHIDRA_INSTALL_DIR"
    exit
fi
gradle build
#
# Copy build classes to bin
#
cp -ar build/classes/java/main bin/

#
# Copy jars, etc to Ghidra install dir
#
GHIDRA_EXTENSION_DIR=$GHIDRA_INSTALL_DIR/../Extensions
mkdir -p $GHIDRA_EXTENSION_DIR/RESimGhidraPlugins/lib
cp -a build/libs/RESimGhidraPlugins.jar $GHIDRA_EXTENSION_DIR/RESimGhidraPlugins/lib
cp -a lib/*.jar $GHIDRA_EXTENSION_DIR/RESimGhidraPlugins/lib
cp extension.properties $GHIDRA_EXTENSION_DIR/RESimGhidraPlugins/
cp -aR data $GHIDRA_EXTENSION_DIR/RESimGhidraPlugins/
echo "RESim Ghidra extension installed in $GHIDRA_INSTALL_DIR"
