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
cp -aR build/classes/java/main $GHIDRA_INSTALL_DIR/Extensions/RESimGhidraPlugins/bin
cp extension.properties $GHIDRA_INSTALL_DIR/Extensions/RESimGhidraPlugins/
cp -aR data $GHIDRA_INSTALL_DIR/Extensions/RESimGhidraPlugins/
