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
from ghidra.program.model.symbol import ReferenceManager
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.data import Structure
from ghidra.program.model.data import StructureDataType

# commandline args given to the script
# array(java.lang.String, [u'fdf sdf df****])
args = getScriptArgs()
print(args)

# prints the current program name
program = currentProgram
analyzeAll(program)
print(program)
minAddress = currentProgram.getMinAddress()
listing = currentProgram.getListing()
codeUnit = listing.getCodeUnitAt(minAddress)
print(codeUnit)
# set the filename to store the output text file
# change this to your preferable location
# filename = "/projects/zephyr/Ruturaj/ghidra_learning/" + program.getName() + ".txt"
# print(filename)
# ref manager
refmanager = program.referenceManager

# Decompile interface object
decompinterface = DecompInterface()
# open the program to decompile using the particular object
decompinterface.openProgram(program);

# A dictionary to store the varible metadata
# varmetada = {owner:{parameter:value}}
varmetada = {}

# This function predicts the varible datatypes
def predictdtype(dtype, variable, parameters):
    owner = "scalar"
    for parameter in parameters:
        if parameter.getLength() == variable.getLength():
            owner = parameter.getDataType().getDefaultLabelPrefix()
            dtype = parameter.getDataType()
            parameters.remove(parameter)
            break
    return dtype, owner, parameters

def predictownertype(prefix):
    if "PTR" in str(prefix):
        return "pointer"
    elif "ARRAY" in str(prefix):
        return "array"
    else:
        return "scalar"

# this can be modified later in case, registers need to be tracked

# prints varible names along with some other information
def printvariable(variables, parameters):
    print(variables)
    for variable in variables:
        # print("variable: {}".format(variable))
        # get the offset of the varible on the stack
        offset = variable.getStackOffset()
        # get the varibale data type
        # variable.getDataType().adjustComponents()
        # get the datatype
        print(variable.getDataType().getDefaultLabelPrefix())
        print(variable.getDataType().getDefaultAbbreviatedLabelPrefix())
        dtype = variable.getDataType().getDisplayName()
        print("dtype: {}".format(dtype))
        if "undefined" in str(dtype):
            dtype, owner, parameters = predictdtype(dtype, variable, parameters)
            owner = predictownertype(owner)
        else:
            # get the ownertype
            owner = predictownertype(variable.getDataType().getDefaultLabelPrefix())
        # print("dtype: {}".format(dtype.getDisplayName()))

        try:
            # if the type is structure
            print("variable storage: {}".format(variable.getDataType().getDefinedComponents()))
            struct_vars = {}
            for component in variable.getDataType().getDefinedComponents():
                offset = variable.getStackOffset() + component.getOffset()
                owner = predictownertype(component.getDataType().getDefaultLabelPrefix())
                size = component.getLength()
                struct_vars[offset] = component.getFieldName()
                varmetada[str(component.getFieldName())] = {"offset":offset + 8, "dtype":str(component.getDataType()).replace(" ", ""), "owner":owner, "size":size}
            for ref in refmanager.getReferencesTo(variable):
                print("ref: {}-{} : {}".format(ref.getFromAddress(), ref.getSource(), ref.getToAddress()))
                for struct_var in struct_vars:
                    print(struct_var)
                    print(ref.getToAddress().getOffset())
                    print(ref.getReferenceType())
                    if struct_var == ref.getToAddress().getOffset():
                        with open("test.txt", "a") as f:
                            f.write(str(ref.getFromAddress()) + " " + struct_vars[struct_var] + "\n")
            continue
        except:
            for ref in refmanager.getReferencesTo(variable):
                # checks to avoid the accesses
                # TODO: same check needed for the pointer
                print(ref)
                if str(ref.getReferenceType()) == "DATA":
                    continue
                if str(ref.getReferenceType()) == "READ" and owner == "scalar":
                    continue
                if str(ref.getReferenceType()) == "READ" and owner == "pointer":
                    register = getInstructionAt(ref.getFromAddress()).getRegister(0).getBaseRegister()
                    print(register)
                    predictvar(ref.getFromAddress().next(), variable.getName(), register)
                    continue
                print(ref.getReferenceType())
                print("ref: {}-{} : {}".format(ref.getFromAddress(), ref.getSource(), ref.getToAddress()))
                with open("test.txt", "a") as f:
                    f.write(str(ref.getFromAddress()) + " " + variable.getName() + "\n")

        # get the varibale name/ owner
        varname = variable.getName()
        print("TYPE::::::::::::::::::::::::::::")
        print(variable.getSymbol())
        # size of the variable
        size = variable.getLength()
        varmetada[str(varname)] = {"offset":offset + 8, "dtype":str(dtype).replace(" ", ""), "owner":owner, "size":size}

def instPrint(entrypoint):
    cur = entrypoint
    while cur:
        inst = getInstructionAt(cur)
        if inst:
            print("Number of operands: {}".format(inst.getNumOperands()))
            for i in inst.getPcode():
                print(i.getMnemonic())
            print("inst: {}".format(inst))
            if str(inst) == "RET":
                break
        cur = cur.next()
# This functions predicts the variables in the instructions
def predictvar(entrypoint, name, register):
    print("####################")
    regs = [register]
    cur = entrypoint
    print(name)
    # offsets = {}
    # offsets = {variable.getName():hex(variable.getStackOffset() + 8) for variable in variables}
    while cur:
        inst = getInstructionAt(cur)
        if inst:
            # If the mnemonic is any of these, then don't proceed
            if inst.getMnemonicString() == "PUSH" or inst.getMnemonicString() == "CALL":
                cur = cur.next()
                continue
            print("mnemonic: {}".format(inst.getMnemonicString()))
            print("Number of operands: {}".format(inst.getNumOperands()))
            print(inst.getScalar(1))
            inst_info = [str(i.getMnemonic()) for i in inst.getPcode()]
            print(inst_info)
            # stop the look for any load in the
            if "LOAD" in inst_info:
                if inst.getRegister(0):
                    print("{} : {}".format(inst.getRegister(0).getBaseRegister(), register))
                    if str(inst.getRegister(0).getBaseRegister()) == str(register):
                        print("%%%%%%%%%%%%%%%%%%%%%%%%")
                        print(inst)
                        print(inst.getOpObjects(0))
                        print(inst.getOpObjects(1))
                        print("%%%%%%%%%%%%%%%%%%%%%%%%")
                        # temporary registers
                        registers = []
                        for ob in inst.getOpObjects(1):
                            try:
                                registers.append(ob.getBaseRegister())
                            except:
                                pass
                        decision = list(set(regs) & set(registers))
                        if decision:
                            with open("test.txt", "a") as f:
                                f.write(str(cur) + " " + name + "\n")
                        break
            # if there is a store, then print
            elif "STORE" in inst_info:
                if int(inst.getNumOperands()) == 2:
                    if inst.getOperandRefType(0).isWrite():
                        print("***************************")
                        print(inst)
                        print(inst.getOpObjects(0))
                        print(inst.getOpObjects(1))
                        print("***************************")
                        registers = []
                        for ob in inst.getOpObjects(0):
                            try:
                                registers.append(ob.getBaseRegister())
                            except:
                                pass
                        decision = list(set(regs) & set(registers))
                        if decision:
                            with open("test.txt", "a") as f:
                                f.write(str(cur) + " " + name + "\n")
            # if their is a register copy
            elif "COPY" in inst_info and len(inst_info) == 1:
                if inst.getRegister(1):
                    if inst.getRegister(1).getBaseRegister() == register:
                        regs.append(inst.getRegister(0))
            # useful to get the instruction representation
            # print(getCodeUnitFormat().getOperandRepresentationList(inst, 1))
            # print(list(getReferencesFrom(cur)))
            # for ref in list(getReferencesFrom(cur)):
            #     print(refmanager.getReferencedVariable(ref))
            # print(getCodeUnitFormat().getRepresentationString(inst))

            if str(inst) == "RET":
                break
        cur = cur.next()
    print("####################")

# get the function iterator object
functions = program.getFunctionManager().getFunctions(True)
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
    print("loc: {}".format(list(function.getLocalVariables())))
    printvariable(variables, parameters)
    # instPrint(entrypoint)
    # predictvar(entrypoint, variables)
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
