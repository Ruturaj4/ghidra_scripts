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
print(codeUnit)
# set the filename to store the output text file
# change this to your preferable location
# filename = "/projects/zephyr/Ruturaj/ghidra_learning/" + program.getName() + ".txt"
# print(filename)

# Decompile interface object
decompinterface = DecompInterface()
# open the program to decompile using the particular object
decompinterface.openProgram(program);

# A dictionary to store the varible metadata
# varmetada = {owner:{parameter:value}}
varmetada = {}

# This function predicts the varible datatypes
def predictdtype(dtype, variable, parameters):
    for parameter in parameters:
        if parameter.getLength() == variable.getLength():
            dtype = parameter.getDataType()
            parameters.remove(parameter)
            break
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
    for variable in variables:
        # print("variable: {}".format(variable))
        # get the offset of the varible on the stack
        offset = variable.getStackOffset()
        # get the varibale data type
        dtype = variable.getDataType().getDisplayName()
        # if "undefined" in str(dtype):
        #     dtype, parameters = predictdtype(dtype, variable, parameters)
        # print("dtype: {}".format(dtype.getDisplayName()))
        # get the ownertype
        owner = predictownertype(variable, dtype)
        # get the varibale name/ owner
        varname = variable.getName()
        # size of the variable
        size = variable.getLength()
        varmetada[str(varname)] = {"offset":offset + 8, "dtype":str(dtype).replace(" ", ""), "owner":owner, "size":size}

# This functions predicts the variables in the instructions
def predictvar(entrypoint, variables):
    cur = entrypoint
    offsets = {}
    # offsets = {hex(variable.getStackOffset() + 8):variable.getName() for variable in variables}
    for variable in variables:
        if "-" in str(hex(variable.getStackOffset() + 8)):
            offsets[str(hex(variable.getStackOffset() + 8)) + "]"] = variable.getName()
        else:
            offsets[str(hex(variable.getStackOffset() + 8)) + "]"] = variable.getName()
    print("Offset: {}".format(offsets))
    while cur:
        inst = getInstructionAt(cur)
        if inst:
            # print(inst.getResultObjects())
            # print(inst.getPcode())
            print("{} {}".format(cur, inst))
            detect = [offset for offset in offsets if offset in str(inst)]
            if detect:
                print(detect)
                # if there is only one memory operand
                if len(detect) == 1:
                    # print(varmetada)
                    try:
                        if varmetada[str(offsets[detect[0]])]["owner"] == "pointer" and inst.getRegister(0):
                            print(inst.getRegister(0))
                            reg = str(inst.getRegister(0).getBaseRegister())
                            next = inst.getNext()
                            while next:
                                print(next)
                                print(reg)
                                if str(next.getRegister(0).getBaseRegister()) == reg:
                                    try:
                                        # check when the register containing pointer has been used in
                                        # future instructions
                                        print(str(next).split(","))
                                        if reg in str(next).split(",")[-1]:
                                            break
                                    except:
                                        pass
                                    next = next.getNext()
                                else:
                                    break
                            with open("test.txt", "a") as f:
                                f.write("{} {}\n".format(str(next.getNext().getFallFrom()).lstrip("0"), offsets[detect[0]]))
                            cur = cur.next()
                            continue
                    except:
                        # if arg 0 is not a register
                        cur = cur.next()
                        continue
                # the conditions to satisfy before printing
                if not str(inst).split()[0] == "LEA":
                    with open("test.txt", "a") as f:
                        f.write("{} {}\n".format(str(cur).lstrip("0"), offsets[detect[0]]))
            if str(inst) == "RET":
                break
        cur = cur.next()

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
        f.write(str(function.getStackFrame().getFrameSize() - 8) + "\n")
    print("frame size: {}".format(function.getStackFrame().getFrameSize()))
    # get the starting address of the function
    entrypoint = function.getEntryPoint()
    tokengrp = decompinterface.decompileFunction(function, 0, ConsoleTaskMonitor())
    print(tokengrp.getCCodeMarkup())
    print(list(function.getParameters()))
    # print varibale names
    parameters = list(function.getParameters())
    variables = list(function.getStackFrame().getStackVariables())

    printvariable(variables, parameters)
    predictvar(entrypoint, variables)
    with open("test.txt", "a") as f:
        f.write("\n")
        for k in varmetada:
            f.write(str(varmetada[k]["offset"]) + " ")
            f.write(varmetada[k]["dtype"] + " ")
            f.write(varmetada[k]["owner"] + " ")
            f.write(k + " ")
            f.write(str(varmetada[k]["size"]) + "\n")
        f.write("\n")
    varmetada = {}
    print(currentProgram.getListing().getNumCodeUnits())
    # printtokens(list(function.getStackFrame().getStackVariables()), tokengrp.getCCodeMarkup())
    print("ctg: {} and entrypoint: {}".format(list(function.getStackFrame().getStackVariables()), entrypoint))
