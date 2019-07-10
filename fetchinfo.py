# Import everything
# import java
# import ghidra
from ghidra.app.util.headless import HeadlessScript
from ghidra.app.decompiler import ClangNode
from ghidra.app.decompiler import ClangToken
from ghidra.app.decompiler import ClangLine
from ghidra.app.decompiler import ClangTokenGroup
from  ghidra.app.decompiler import DecompInterface
from ghidra.app.decompiler import DecompileResults
from ghidra.program.model.address import Address
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.listing import Function
from ghidra.program.model.listing import FunctionIterator
from ghidra.program.model.listing import InstructionIterator
from ghidra.program.model.listing import Program
from ghidra.program.model.listing import Variable
from ghidra.program.model.pcode import HighFunction
from ghidra.program.model.pcode import HighSymbol
from ghidra.program.model.pcode import HighVariable
from ghidra.program.model.pcode import LocalSymbolMap
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.pcode import Varnode
from ghidra.program.model.symbol import Symbol
from ghidra.program.model.symbol import Reference
from ghidra.program.model.symbol import ReferenceIterator
from ghidra.util.task import ConsoleTaskMonitor

# commandline args given to the script
# array(java.lang.String, [u'fdf sdf df****])
args = getScriptArgs()
print(args)

# prints the current program name
program = currentProgram
print(program)

minAddress = currentProgram.getMinAddress()
listing = currentProgram.getListing()
codeUnit = listing.getCodeUnitAt(minAddress)
print(listing)
# set the filename to store the output text file
# change this to your preferable location
# filename = "/projects/zephyr/Ruturaj/ghidra_learning/" + program.getName() + ".txt"
# print(filename)

# Decompile interface object
decompinterface = DecompInterface()
# open the program to decompile using the particular object
decompinterface.openProgram(program);

def printtokens(node):
    # let's define a dictionary here
    dic = {}
    stack = []
    current = node
    index = 0
    while current:
        if current.numChildren() == 0 and isinstance(current, ClangToken):
            token = current
            try:
                tokenString = str(token)
                # print(tokenString)
                # print(current.toString())
                if (tokenString not in dic):
                    dic[str(current)] = set()
                    # print(dic)
                insAddr = str(token.getPcodeOp().getSeqnum().getTarget())
                # print(insAddr)
                dic[tokenString].add(insAddr)
            except:
                pass
            current = current.Parent()
            index = stack.pop()
            index += 1
        else:
            if index == current.numChildren():
                current = current.Parent()
                if stack:
                    index = stack.pop()
                index += 1
            else:
                current = current.Child(index)
                stack.append(index)
                index = 0
    print(dic)

# This function predicts the varible datatypes
def predictdtype(variable, parameters):
    for parameter in parameters:
        if parameter.getLength() == variable.getLength():
            dtype = parameter.getDataType()
            parameters.remove(parameter)
            break
    print(dtype)
    return dtype, parameters

def predictownertype(variable, dtype):
    if "*" in str(dtype):
        return "pointer"
    elif "[" in str(dtype):
        return "array"
    else:
        return "scalar"

# prints varible names along with some other information
def printvariable(variables, parameters):
    with open("test.txt", "a") as f:
        for variable in variables:
            print("variable: {}".format(variable))
            # get the offset of the varible on the stack
            offset = variable.getStackOffset()
            # get the varibale data type
            dtype = variable.getDataType()
            if "undefined" in str(dtype):
                dtype, parameters = predictdtype(variable, parameters)
            # get the ownertype
            owner = predictownertype(variable, dtype)
            # get the varibale name/ owner
            varname = variable.getName()
            # start point on the stack
            start = variable.getLength()
            f.write(str(offset + 8) + " ")
            f.write(str(dtype).replace(" ", "") + " ")
            f.write(owner + " ")
            f.write(str(varname) + " ")
            f.write(str(start) + "\n")
        f.write("\n")

# get the function iterator object
functions = program.getFunctionManager().getFunctions(True);
# Get the functions having a call stack
# checks are needed only if the function has a call stack
functions = [function for function in functions if function.getStackFrame().getStackVariables() and function.getName() != "_start"]
# write the total number of functions into a file
with open("test.txt", "w") as f:
    f.write(str(len(functions)) + "\n\n")
for function in functions:
    # Write the function name
    print(function.getName())
    with open("test.txt", "a") as f:
        f.write(function.getName() + "\n")
        # The stack size is 8 bytes more when using ghidra, hence reducing the size
        f.write(str(function.getStackFrame().getFrameSize() - 8) + "\n\n")
    print("frame size: {}".format(function.getStackFrame().getFrameSize()))
    entrypoint = function.getEntryPoint()
    tokengrp = decompinterface.decompileFunction(function, 0, ConsoleTaskMonitor())
    print(tokengrp.getCCodeMarkup())
    print(list(function.getParameters()))
    # print varibale names
    parameters = list(function.getParameters())
    printvariable(list(function.getStackFrame().getStackVariables()), parameters)
    print(currentProgram.getListing().getNumCodeUnits())
    print(entrypoint)
    printtokens(tokengrp.getCCodeMarkup())
    print("ctg: {} and entrypoint: {}".format(list(function.getStackFrame().getStackVariables()), entrypoint))
    # for instruction in currentProgram.getListing().InstructionIterator():
    #     print(instruction)
    cur = entrypoint
    while cur:
        inst = getInstructionAt(cur)
        if inst:
            # print(inst.getResultObjects())
            # print(inst.getPcode())
            print("{} {}".format(cur, inst))
            if str(inst) == "RET":
                break
        cur = cur.next()
