#!/bin/bash
if [ -f ~/.config/ghidra/ghidra_12.1.2_PUBLIC/Extensions/RESimPluginY/data/commands.py ]; then
    cp ~/.config/ghidra/ghidra_12.1.2_PUBLIC/Extensions/RESimPluginY/data/commands.py ./Ghidra/Debug/Debugger-agent-gdb/pypkg/src/ghidragdb/
else
    echo "Not ghidra 12.1.2, ghidragdb/commands.py not updated."
fi
