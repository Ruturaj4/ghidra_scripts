from  ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# get the current program
# here currentProgram is predefined

program = currentProgram
decompinterface = DecompInterface()
decompinterface.openProgram(program);
functions = program.getFunctionManager().getFunctions(True)
for function in list(functions):
    print(function)
    # decompile each function
    tokengrp = decompinterface.decompileFunction(function, 0, ConsoleTaskMonitor())
    print(tokengrp.getDecompiledFunction().getC())
