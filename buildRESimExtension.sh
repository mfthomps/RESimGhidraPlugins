#!/bin/bash
#
# Build the RESim Ghidra extension plugins and install them into the GHIDRA_INSTALL_DIR
# and the GHIDRA_DEV_DIR
#
echo "GHIDRA_INSTALL_DIR is $GHIDRA_INSTALL_DIR" 
if [ -z $GHIDRA_INSTALL_DIR ]; then
    echo "Must define GHIDRA_INSTALL_DIR"
    exit
fi
gradle build
GHIDRA_EXTENSION_DIR=$GHIDRA_INSTALL_DIR/../Extensions
mkdir -p $GHIDRA_EXTENSION_DIR/RESimGhidraPlugins/lib
cp -a build/libs/RESimGhidraPlugins.jar $GHIDRA_EXTENSION_DIR/RESimGhidraPlugins/lib
cp -a lib/*.jar $GHIDRA_EXTENSION_DIR/RESimGhidraPlugins/lib
cp extension.properties $GHIDRA_EXTENSION_DIR/RESimGhidraPlugins/
cp -aR data $GHIDRA_EXTENSION_DIR/RESimGhidraPlugins/
echo "RESim Ghidra extension installed in $GHIDRA_INSTALL_DIR"
#
#  Allow testing in dev system (repo) without reinstalling plugins each time.
#
echo "GHIDRA_DEV_DIR is $GHIDRA_DEV_DIR" 
if [ -z $GHIDRA_DEV_DIR ]; then
    echo "No GHIDRA_DEV_DIR defined, no support for dev mode testing."
    echo "Only run Ghidra from $GHIDRA_INSTALL_DIR."
    exit
fi
mkdir -p $GHIDRA_DEV_DIR/Ghidra/Extensions/RESimGhidraPlugins/
cp -aR ./build/classes/java/main/resim $GHIDRA_DEV_DIR/Ghidra/Extensions/RESimGhidraPlugins/bin/main
cp -aR ./bin $GHIDRA_DEV_DIR/Ghidra/Extensions/RESimGhidraPlugins/
cp extension.properties $GHIDRA_DEV_DIR/Ghidra/Extensions/RESimGhidraPlugins/
cp -aR data $GHIDRA_DEV_DIR/Ghidra/Extensions/RESimGhidraPlugins/
