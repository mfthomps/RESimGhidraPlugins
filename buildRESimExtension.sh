#!/bin/bash
#
# Build the RESim Ghidra extension plugins and install them into the GHIDRA_INSTALL_DIR
#
echo "GHIDRA_INSTALL_DIR is $GHIDRA_INSTALL_DIR" 
if [ -z $GHIDRA_INSTALL_DIR ]; then
    echo "Must define GHIDRA_INSTALL_DIR"
    exit
fi
gradle build
GHIDRA_EXTENSION_DIR=$GHIDRA_INSTALL_DIR/../Extensions
mkdir -p $GHIDRA_EXTENSION_DIR/RESimGhidraPlugins/lib
cp -aR build/libs/RESimGhidraPlugins.jar $GHIDRA_EXTENSION_DIR/RESimGhidraPlugins/lib
cp -a lib/*.jar $GHIDRA_EXTENSION_DIR/RESimGhidraPlugins/lib
cp extension.properties $GHIDRA_EXTENSION_DIR/RESimGhidraPlugins/
cp -aR data $GHIDRA_EXTENSION_DIR/RESimGhidraPlugins/
