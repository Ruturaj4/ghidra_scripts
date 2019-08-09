# Import everything
# import java
# import ghidra
import json
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
# print(args)

# prints the current program name
program = currentProgram
analyzeAll(program)
minAddress = currentProgram.getMinAddress()
listing = currentProgram.getListing()
codeUnit = listing.getCodeUnitAt(minAddress)
# print(codeUnit)
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
# A dictionary to store addresses and references
# addrmetada = {function:{address:ref}}
addrmetada = {}
# A dictionary to store the namespace metadata for static variables
# namespacemetada = {}
namespacemetada = {}
# global metadata
metadata = {".global":[]}

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
    print("prefix: {}".format(prefix))
    # special case for a pointer array
    if str(prefix) == "PTR_ARRAY":
        return "array"
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
        # print(variable.getDataType().getDefaultLabelPrefix())
        # print(variable.getDataType().getDefaultAbbreviatedLabelPrefix())
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
                if not str(fun_name) in metadata:
                    metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[]}
                metadata[str(fun_name)]["variables"].append({"owner":str(component.getFieldName()), "offset":offset + 8, "dtype":str(component.getDataType()).replace(" ", ""), "ownertype":owner, "size":size})
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
                        addrmetada.update({str(ref.getFromAddress()).lstrip("0"):str(struct_vars[struct_var])})
                        if not str(fun_name) in metadata:
                            metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[]}
                        metadata[str(fun_name)]["addresses"].append({"address":str(ref.getFromAddress()).lstrip("0"), "owner":str(struct_vars[struct_var])})
                    elif owner == "array":
                        addrmetada.update({str(ref.getFromAddress()).lstrip("0"):str(struct_vars[struct_var])})
                        if not str(fun_name) in metadata:
                            metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[]}
                        metadata[str(fun_name)]["addresses"].append({"address":str(ref.getFromAddress()).lstrip("0"), "owner":str(struct_vars[struct_var])})
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
                    if not getInstructionAt(ref.getFromAddress()).getMnemonicString() == "MOV":
                        continue
                    register = getInstructionAt(ref.getFromAddress()).getRegister(0).getBaseRegister()
                    predictvar(ref.getFromAddress().next(), variable.getName(), register, fun_name)
                    continue
                print(ref.getReferenceType())
                print("ref: {}-{} : {}".format(ref.getFromAddress(), ref.getSource(), ref.getToAddress()))
                addrmetada.update({str(ref.getFromAddress()).lstrip("0"):str(variable.getName())})
                if not str(fun_name) in metadata:
                    metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[]}
                metadata[str(fun_name)]["addresses"].append({"address":str(ref.getFromAddress()).lstrip("0"), "owner":str(variable.getName())})
        # get the varibale name/ owner
        varname = variable.getName()
        # size of the variable
        size = variable.getLength()
        if not str(fun_name) in metadata:
            metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[]}
        metadata[str(fun_name)]["variables"].append({"owner":str(varname), "offset":offset + 8, "dtype":str(dtype).replace(" ", ""), "ownertype":owner, "size":size})
        varmetada[str(varname)] = {"offset":offset + 8, "dtype":str(dtype).replace(" ", ""), "owner":owner, "size":size}

# This function is used to predict the arrays
def predictarrvar(entrypoint, fun_name):
    cur = entrypoint
    # varmetada with offset as keys and variable name as values
    offsetvarmetada = {v["offset"]:k for k,v in varmetada.iteritems()}

    while cur:
        inst = getInstructionAt(cur)
        if inst:
            if getFunctionContaining(cur) is None:
                break
            if getFunctionContaining(cur).getName() != fun_name:
                break
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
                            addrmetada.update({str(cur).lstrip("0"):str(offsetvarmetada[off])})
                            if not str(fun_name) in metadata:
                                metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[]}
                            metadata[str(fun_name)]["addresses"].append({"address":str(cur).lstrip("0"), "owner":str(offsetvarmetada[off])})
                # for the load instruction
                if len(inst.getOpObjects(1)) >= 3:
                    for off in offsetvarmetada:
                        if hex(off) in [str(x) for x in inst.getOpObjects(1)]:
                            addrmetada.update({str(cur).lstrip("0"):str(offsetvarmetada[off])})
                            if not str(fun_name) in metadata:
                                metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[]}
                            metadata[str(fun_name)]["addresses"].append({"address":str(cur).lstrip("0"), "owner":str(offsetvarmetada[off])})
        cur = cur.next()

# This function is used to predict the pointers
def predictvar(entrypoint, name, register, fun_name):
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
            if getFunctionContaining(cur) is None:
                break
            # quit if the instruction is out of the function
            print(getFunctionContaining(cur))
            if getFunctionContaining(cur).getName() != fun_name:
                break
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
                        # temporary registers
                        registers = []
                        for ob in inst.getOpObjects(1):
                            try:
                                registers.append(ob.getBaseRegister())
                            except:
                                pass
                        decision = list(set(regs) & set(registers))
                        if decision:
                            addrmetada.update({str(cur).lstrip("0"):str(name)})
                            if not str(fun_name) in metadata:
                                metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[]}
                            metadata[str(fun_name)]["addresses"].append({"address":str(cur).lstrip("0"), "owner":str(name)})
                        break
            # if there is a store, then print
            elif "STORE" in inst_info:
                if int(inst.getNumOperands()) == 2:
                    if inst.getOperandRefType(0).isWrite():
                        registers = []
                        for ob in inst.getOpObjects(0):
                            try:
                                registers.append(ob.getBaseRegister())
                            except:
                                pass
                        decision = list(set(regs) & set(registers))
                        if decision:
                            addrmetada.update({str(cur).lstrip("0"):str(name)})
                            if not str(fun_name) in metadata:
                                metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[]}
                            metadata[str(fun_name)]["addresses"].append({"address":str(cur).lstrip("0"), "owner":str(name)})
            # if their is a register copy
            elif "COPY" in inst_info and len(inst_info) == 1:
                # Add this if required
                # if inst.getRegister(0):
                #     if inst.getRegister(0).getBaseRegister() == register:
                #         with open("test.txt", "a") as f:
                #             f.write(str(cur).lstrip("0") + " " + str(name) + "\n")
                if inst.getRegister(1):
                    if inst.getRegister(1).getBaseRegister() == register:
                        regs.append(inst.getRegister(0))
            # useful to get the instruction representation
            # print(getCodeUnitFormat().getOperandRepresentationList(inst, 1))
            # print(list(getReferencesFrom(cur)))
            # print(getCodeUnitFormat().getRepresentationString(inst))
        cur = cur.next()

# get globals/static symbols
# these are the symbols which are defined in the data section
def get_data_symbols():
    symbols = set(program.getSymbolTable().	getAllSymbols(True))
    ignore_symbols = { "_start", "__libc_start_main", "__libc_csu_init", "_init",  "exit",
    "_dl_relocate_static_pie", "_fini", "__libc_csu_fini", "malloc", "calloc", "realloc", "free",
    "gets", "printf", "puts","fgets", ".plt", "atoi"}
    for s in symbols:
        if str(s) in ignore_symbols:
            continue
        # instructions to be referenced from the global variables
        ref_instructions = [getInstructionAt(x.getFromAddress()) for x in s.getReferences()]
        if ref_instructions and not all(x is None for x in ref_instructions):
            try:
                # let symbol to be added be s
                print(type(s.getObject()))
                print(s.isExternal())
                print(s.isDynamic())
                print(s.isExternalEntryPoint())
                print(s.isGlobal())
                address = str(s.getAddress()).lstrip("0")
                size = str(s.getObject().getLength())
                print(size)
                # where is this variable? is it in the global namespace or is in the function namespace
                if s.isGlobal():
                    namespace = ".global"
                else:
                    namespace = str(s.getPath()[0])
                print(s.isGlobal())
                print(type(s.getObject()))
                dtype = s
                owner = predictownertype(s.getObject().getDataType().getDefaultLabelPrefix())
                # print("datatype: {}".format(s.getObject().getDataType()))
                # most of the cases fail here, if they don't belong to any instructions
                print([getInstructionAt(x.getFromAddress()) for x in s.getReferences()])
                addresses = [x.getFromAddress() for x in s.getReferences()]
                # print(addresses)
                # predict type
                if s.getObject().getParent():
                    print("&&&&&&&&&&&&&&&&&&&&&")
                    print("parent: {}".format(s.getObject().getParent().getParent()))
                    # dtype = s.getObject().getParent().getPathName()
                    # decide their namespace - it will be same as the their parent function
                    if s.isGlobal():
                        namespace = str(getFunctionContaining(s.getReferences()[0].getFromAddress()).getName())
                    if s.getObject().getParent().isArray():
                        dtype = s.getObject().getParent().getPathName()
                        size = str(s.getObject().getParent().getLength())
                        address = str(s.getObject().getParent().getAddress()).lstrip("0")
                    owner = s.getObject().getParent()
                    owner = predictownertype(owner.getBaseDataType().getDefaultLabelPrefix())
                    print("&&&&&&&&&&&&&&&&&&&&&")
                try:
                    # first variable in a structure
                    print("variable storage: {}".format(list(s.getObject().getDataType().getDefinedComponents())))
                    for component in s.getObject().getDataType().getDefinedComponents():
                        print(component.	getDefaultFieldName())
                        owner = predictownertype(component.getDataType().getDefaultLabelPrefix())
                        size = str(component.getLength())
                        dtype = str(dtype) + "." + str(component.getFieldName())
                        namespacemetada[str(component.getFieldName())] = {"dtype":str(component.getDataType()).replace(" ", ""), "owner":owner, "size":size}
                        print(owner)
                        break
                except:
                    pass
                for ref in s.getReferences():
                    print(getInstructionAt(x.getFromAddress()))
                    if getInstructionAt(x.getFromAddress()) == None:
                        continue
                    print(owner)
                    print("ref type: {}".format(ref.getReferenceType()))
                    if str(ref.getFromAddress()) == "Entry Point":
                        continue
                    fun_name = getFunctionContaining(ref.getFromAddress()).getName()
                    if str(ref.getReferenceType()) == "EXTERNAL":
                        print("\n")
                        continue
                    if str(ref.getReferenceType()) == "INDIRECTION":
                        print("\n")
                        continue
                    if str(ref.getReferenceType()) == "DATA":
                        print("\n")
                        continue
                    if str(ref.getReferenceType()) == "READ" and owner == "scalar":
                        print("\n")
                        continue
                    if str(ref.getReferenceType()) == "READ" and owner == "pointer":
                        if not getInstructionAt(ref.getFromAddress()).getMnemonicString() == "MOV":
                            continue
                        register = getInstructionAt(ref.getFromAddress()).getRegister(0).getBaseRegister()
                        print(register)
                        predictvar(ref.getFromAddress(), dtype, register, fun_name)
                        continue
                    print(ref.getReferenceType())
                    print("ref: {}-{} : {}".format(ref.getFromAddress(), ref.getSource(), ref.getToAddress()))
                    if str(fun_name) not in metadata:
                        metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[]}
                    metadata[str(fun_name)]["addresses"].append({"address":str(ref.getFromAddress()).lstrip("0"), "owner":str(dtype)})
                    print("\n")
                if namespace == ".global":
                    metadata[".global"].append({"owner":str(dtype),"datatype":owner, "address":address, "size":size})
                    print("\n")
                    continue
                elif str(namespace) not in metadata:
                    metadata[str(namespace)] = {"variables":[], "addresses":[], "namespace":[]}
                metadata[str(namespace)]["namespace"].append({"owner":str(dtype),"datatype":owner, "address":address, "size":size})
                print("\n")
            except AttributeError:
                pass

get_data_symbols()

# get the function iterator object
functions = program.getFunctionManager().getFunctions(True)
ignore_functions = { "_start", "__libc_start_main", "__libc_csu_init", "_init",  "exit",
"_dl_relocate_static_pie", "_fini", "__libc_csu_fini", "malloc", "calloc", "realloc", "free",
"gets", "printf", "puts", "fgets", "atoi"}
# Get the functions having a call stack
# checks are needed only if the function has a call stack
functions = [function for function in functions if str(function) not in ignore_functions and function.getName() in fun_blocks]
print(functions)
# Iterate through all the functions
for function in functions:
    # Get code markup i.e. decompiled code
    tokengrp = decompinterface.decompileFunction(function, 0, ConsoleTaskMonitor())
    # print(tokengrp.getDecompiledFunction().	getC())
    # compute the basic building blocks
    print(fun_blocks[function.getName()])
    # Useful to get the function size
    # The stack size is 8 bytes more when using ghidra, hence reducing the size
    # f.write(str(function.getStackFrame().getFrameSize() - 8) + "\n")
    print("frame size: {}".format(function.getStackFrame().getFrameSize()))
    # get the starting address of the function
    entrypoint = function.getEntryPoint()

    print(list(function.getParameters()))
    # print varibale names
    parameters = list(function.getParameters())
    variables = list(function.getStackFrame().getStackVariables())
    print("loc: {}".format(list(function.getLocalVariables())))
    print(function)
    printvariable(variables, parameters, function.getName())
    # predictvar(entrypoint, variables)
    # predict the dynamic array accesses like
    # mov DWORD PTR [rbp+rax*4-0x30],edx
    predictarrvar(entrypoint, function.getName())
    varmetada = {}
    addrmetada = {}
    print("ctg: {} and entrypoint: {}".format(list(function.getStackFrame().getStackVariables()), entrypoint))
# for tree in currentProgram.getTreeManager().getTreeNames():
#     print(tree)
#     print(currentProgram.getTreeManager().getFragment(tree, ".text"))
#     mod = currentProgram.getTreeManager().getRootModule(tree)
#     print([x.	getName() for x in mod.getChildren()])

# Now create a file so that, it will be readable for c++
with open("test.txt", "w") as f:
    count = len(metadata) - 1
    f.write("{}\n".format(count))
    for k,v in metadata.items():
        if k == ".global":
            continue
        f.write("{}\n".format(k))
        f.write("{}\n".format("addresses"))
        for add in v["addresses"]:
            f.write("{} ".format(add["address"]))
            f.write("{}\n".format(add["owner"]))
        f.write("\n")
        f.write("{}\n".format("locals"))
        for var in v["variables"]:
            f.write("{} {} {} {} {}\n".format(var["offset"], var["dtype"], var["ownertype"], var["owner"], var["size"]))
        f.write("\n")
        f.write("{}\n".format("namespace"))
        for var in v["namespace"]:
            f.write("{} {} {} {} {}\n".format(var["address"], var["datatype"], var["owner"], var["size"]))
        f.write("\n")
    f.write(".global\n")
    for var in metadata[".global"]:
        f.write("{} {} {} {}\n".format(var["address"], var["datatype"], var["owner"], var["size"]))
    f.write("\n")



# Another option is to store the data into a json format
# with open("test.txt", "w") as f:
#     json.dump(metadata, f)
