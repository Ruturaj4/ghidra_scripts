# get the current program
# here currentProgram is predefined

program = currentProgram
functions = program.getFunctionManager().getFunctions(True)
print(list(functions))
