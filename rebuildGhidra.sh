#!/bin/bash
#
# Update and rebuild from a ghidra repo.
# And then extract the distribution into a GHIDRA_INSTALL_DIR
#
here=`pwd`
if [[ -z "$GHIDRA_DEV_DIR" ]]; then
    echo "GHIDRA_DEV_DIR not defined, cannot rebuild Ghidra."
    exit 1
fi
cd $GHIDRA_DEV_DIR
git pull
gradle -I gradle/support/fetchDependencies.gradle init
gradle buildGhidra
cd $GHIDRA_INSTALL_DIR
zip=$(ls -Art $GHIDRA_DEV_DIR/build/dist/*.zip | tail -n 1)
unzip $zip
