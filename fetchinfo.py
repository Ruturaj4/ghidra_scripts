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

# for static blocks
blockiterator = BasicBlockModel(currentProgram).getCodeBlocks(monitor)
fun_blocks = {}

def add_block(function, block):
    if function not in fun_blocks:
         fun_blocks[function] = []
    fun_blocks[function].append(block)

# For each block, look through the function list until we find a match
# This is terribly inefficient (O(N^2))

def basicblocks():
    while blockiterator.hasNext():
        cur_block = blockiterator.next().getMinAddress()
        function = getFirstFunction()
        found = False

        # Search functions until we find a match or run out of functions
        while function is not None:
            b = function.getBody()
            if b.contains(cur_block):
                add_block(function.getName(), cur_block)
                found=True
                break

            # Update function to next and loop again
            function = getFunctionAfter(function)

        # Done searching functions. If we never found it, add to unknown list
        if not found:
            add_block("_unknown", cur_block)

basicblocks()

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
def printvariable(variables, parameters, fun_name):
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
                        if str(ref.getReferenceType()) == "DATA":
                            continue
                        if str(ref.getReferenceType()) == "READ" and owner == "scalar":
                            continue
                        if str(ref.getReferenceType()) == "READ" and owner == "pointer":
                            register = getInstructionAt(ref.getFromAddress()).getRegister(0).getBaseRegister()
                            predictvar(ref.getFromAddress().next(), struct_vars[struct_var], register, fun_name)
                            continue
                        with open("test.txt", "a") as f:
                            f.write(str(ref.getFromAddress()).lstrip("0") + " " + struct_vars[struct_var] + "\n")
                    elif owner == "array":
                        with open("test.txt", "a") as f:
                            f.write(str(ref.getFromAddress()).lstrip("0") + " " + struct_vars[struct_var] + "\n")
            continue
        except:
            for ref in refmanager.getReferencesTo(variable):
                # checks to avoid the accesses
                print(ref)
                if str(ref.getReferenceType()) == "DATA":
                    continue
                if str(ref.getReferenceType()) == "READ" and owner == "scalar":
                    continue
                if str(ref.getReferenceType()) == "READ" and owner == "pointer":
                    register = getInstructionAt(ref.getFromAddress()).getRegister(0).getBaseRegister()
                    predictvar(ref.getFromAddress().next(), variable.getName(), register, fun_name)
                    continue
                print(ref.getReferenceType())
                print("ref: {}-{} : {}".format(ref.getFromAddress(), ref.getSource(), ref.getToAddress()))
                with open("test.txt", "a") as f:
                    f.write(str(ref.getFromAddress()).lstrip("0") + " " + variable.getName() + "\n")

        # get the varibale name/ owner
        varname = variable.getName()
        # size of the variable
        size = variable.getLength()
        varmetada[str(varname)] = {"offset":offset + 8, "dtype":str(dtype).replace(" ", ""), "owner":owner, "size":size}

# This function is used to predict the arrays
def predictarrvar(entrypoint):
    cur = entrypoint
    # varmetada with offset as keys and variable name as values
    offsetvarmetada = {v["offset"]:k for k,v in varmetada.iteritems()}

    while cur:
        inst = getInstructionAt(cur)
        if inst:
            if str(inst) == "RET":
                break
            if not inst.getNumOperands() == 2 or not inst.getMnemonicString() == "MOV":
                cur = cur.next()
                continue
            if all(x in [str(i.getMnemonic()) for i in inst.getPcode()] for x in ['INT_ADD', 'COPY']):
                # for the store instruction
                if len(inst.getOpObjects(0)) >= 3:
                    for off in offsetvarmetada:
                        print(hex(off))
                        if hex(off) in [str(x) for x in inst.getOpObjects(0)]:
                            with open("test.txt", "a") as f:
                                f.write(str(cur).lstrip("0") + " " + offsetvarmetada[off] + "\n")
                # for the load instruction
                if len(inst.getOpObjects(1)) >= 3:
                    for off in offsetvarmetada:
                        if hex(off) in [str(x) for x in inst.getOpObjects(1)]:
                            with open("test.txt", "a") as f:
                                f.write(str(cur).lstrip("0") + " " + offsetvarmetada[off] + "\n")
        cur = cur.next()

# This function is used to predict the pointers
def predictvar(entrypoint, name, register, fun_name):
    print("####################")
    print(fun_blocks[fun_name])
    print(entrypoint)
    add = "ffffffff"
    for block in fun_blocks[fun_name]:
        if (block > entrypoint):
            add = block
            break
    regs = [register]
    cur = entrypoint
    # offsets = {}
    # offsets = {variable.getName():hex(variable.getStackOffset() + 8) for variable in variables}
    while cur:
        inst = getInstructionAt(cur)
        if inst:
            # quit if new static block
            if cur >= add:
                break
            if str(inst) == "RET":
                break
            # If the mnemonic is any of these, then don't proceed
            if inst.getMnemonicString() == "PUSH" or inst.getMnemonicString() == "CALL":
                cur = cur.next()
                continue
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
                                f.write(str(cur).lstrip("0") + " " + name + "\n")
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
                                f.write(str(cur).lstrip("0") + " " + name + "\n")
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
    # compute the basic building blocks
    print(fun_blocks[function.getName()])
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
    printvariable(variables, parameters, function.getName())
    # predictvar(entrypoint, variables)
    # predict the dynamic array accesses like
    # mov DWORD PTR [rbp+rax*4-0x30],edx
    predictarrvar(entrypoint)
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
