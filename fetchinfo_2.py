import re
import os
# to decompile
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
# to rename function
from ghidra.program.model.symbol import SourceType
# to trace basic blocks
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.pcode import HighFunctionDBUtil

# logic to find and rename the main function
ifc = DecompInterface()
ifc.setOptions(DecompileOptions())
ifc.openProgram(currentProgram)
try:
    entryfunction = getGlobalFunctions("entry")[0]
except:
    # if binary has symbols
    if getGlobalFunctions("_start"):
        entryfunction = getGlobalFunctions("_start")[0]
    else:
        exit()
res = ifc.decompileFunction(entryfunction, 60, monitor)
m = re.search("__libc_start_main\((.+?),", res.getCCodeMarkup().toString())
if m.group(1)[0] != "main":
    getGlobalFunctions(m.group(1))[0].setName("main", SourceType.ANALYSIS)

# for static blocks
blockiterator = BasicBlockModel(currentProgram).getCodeBlocks(monitor)
fun_blocks = {}

def add_block(function, block):
    if function not in fun_blocks:
         fun_blocks[function] = []
    fun_blocks[function].append(block)

# For each block, look through the function list until we find a match
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

def storesymbols(function):
    res = ifc.decompileFunction(function, 60, monitor)
    high_func = res.getHighFunction()
    lsm = high_func.getLocalSymbolMap()
    symbols = lsm.getSymbols()
    HighFunctionDBUtil.commitLocalsToDatabase(high_func, SourceType.ANALYSIS)
    HighFunctionDBUtil.commitLocalsToDatabase(high_func, SourceType.ANALYSIS)

# This function predicts the varible datatypes
def predictdtype(dtype, variable, parameters):
    prefix = "scalar"
    # return pointer if undefined8
    if str(dtype) == "undefined8":
        prefix = "PTR"
    # predict from paramters (as they reflect correct type) instead
    for parameter in parameters:
        if parameter.getLength() == variable.getLength():
            # print(parameter)
            # print(variable)
            prefix = parameter.getDataType().getDefaultLabelPrefix()
            dtype = parameter.getDataType()
            parameters.remove(parameter)
            break
    return dtype, prefix, parameters

def predictownertype(prefix):
    # return if a pointer
    if "PTR" in str(prefix):
        return "pointer"
    # return if an array
    if "ARRAY" in str(prefix):
        return "array"
    # return scalar otherwise
    return "scalar"

# global set of accessed varaibles
accessed_vars = set()

# This function is used to predict the pointers
def predictvar(entrypoint, name, register, fun_name, namespace):
    add = "ffffffff"
    for block in fun_blocks[fun_name]:
        if (block > entrypoint):
            add = block
            break
    regs = [register]
    cur = entrypoint
    while cur:
        inst = getInstructionAt(cur)
        if inst:
            # print(inst)
            if getFunctionContaining(cur) is None:
                break
            # quit if the instruction is out of the function
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
            # stop the look for any load
            if "LOAD" in inst_info:
                # remove load instruction right after function call
                if inst.getPrevious().getMnemonicString() == "CALL":
                    if len(inst.getPcode(1)) == 0:
                        cur = cur.next()
                        continue
                if inst.getRegister(0):
                    # if str(inst.getRegister(0).getBaseRegister()) == str(register):
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
                            metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[], "rsp":adjust_off, "entry":fun_entry, "exit":fun_exit}
                        metadata[str(fun_name)]["addresses"].append({"address":str(cur).lstrip("0"), "owner":namespace + "_" + str(name)})
                        accessed_vars.add(namespace + "_" + str(name))
                    break
                else:
                    # handle long double
                    if "FLD" in str(inst):
                        addrmetada.update({str(cur).lstrip("0"):str(name)})
                        if not str(fun_name) in metadata:
                            metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[], "rsp":adjust_off, "entry":fun_entry, "exit":fun_exit}
                        metadata[str(fun_name)]["addresses"].append({"address":str(cur).lstrip("0"), "owner":namespace + "_" + str(name)})
                        accessed_vars.add(namespace + "_" + str(name))
            # if there is a store
            elif "STORE" in inst_info:
                # remove store instruction right after function call
                if inst.getPrevious().getMnemonicString() == "CALL":
                    if str(inst.getOperandRefType(1)) == "DATA":
                        cur = cur.next()
                        continue
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
                                metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[], "rsp":adjust_off, "entry":fun_entry, "exit":fun_exit}
                            metadata[str(fun_name)]["addresses"].append({"address":str(cur).lstrip("0"), "owner":namespace + "_" + str(name)})
                            accessed_vars.add(namespace + "_" + str(name))
            # if their is copy
            elif "COPY" in inst_info and len(inst_info) == 1:
                if inst.getRegister(1):
                    if inst.getRegister(1).getBaseRegister() == register:
                        regs.append(inst.getRegister(0))
        cur = cur.next()

# ref manager is used to find references
refmanager = currentProgram.referenceManager

# prints varible names along with some other information
def printvariable(variables, parameters, fun_name):
    for variable in variables:
        # get the offset of the varible on the stack
        try:
            offset = variable.getStackOffset()
        except:
            continue
        # get the variable data type
        dtype = variable.getDataType().getDisplayName()
        if "undefined" in str(dtype):
            dtype, prefix, parameters = predictdtype(dtype, variable, parameters)
            owner = predictownertype(prefix)
        else:
            owner = predictownertype(variable.getDataType().getDefaultLabelPrefix())
        # if owner == "scalar":
        #     continue
        try:
            # if the type is a structure
            struct_vars = {}
            for component in variable.getDataType().getDefinedComponents():
                offset = variable.getStackOffset() + component.getOffset()
                owner = predictownertype(component.getDataType().getDefaultLabelPrefix())
                size = component.getLength()
                struct_vars[offset] = component.getFieldName()
                if not str(fun_name) in metadata:
                    metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[], "rsp":adjust_off, "entry":fun_entry, "exit":fun_exit}
                metadata[str(fun_name)]["variables"].append({"owner":str(fun_name) + "_" + str(component.getFieldName()), "offset":offset + adjust_off, "dtype":str(component.getDataType()).replace(" ", ""), "ownertype":owner, "size":size})
                varmetada[str(component.getFieldName())] = {"offset":offset + adjust_off, "dtype":str(component.getDataType()).replace(" ", ""), "owner":owner, "size":size}
            for ref in refmanager.getReferencesTo(variable):
                # print("ref: {}-{} : {}".format(ref.getFromAddress(), ref.getSource(), ref.getToAddress()))
                for struct_var in struct_vars:
                    if struct_var == ref.getToAddress().getOffset():
                        if str(ref.getReferenceType()) == "DATA":
                            continue
                        if str(ref.getReferenceType()) == "READ" and owner == "scalar":
                            continue
                        if str(ref.getReferenceType()) == "READ" and owner == "pointer":
                            register = getInstructionAt(ref.getFromAddress()).getRegister(0).getBaseRegister()
                            predictvar(ref.getFromAddress().next(), struct_vars[struct_var], register, fun_name, str(fun_name))
                            continue
                        addrmetada.update({str(ref.getFromAddress()).lstrip("0"):str(struct_vars[struct_var])})
                        if not str(fun_name) in metadata:
                            metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[], "rsp":adjust_off, "entry":fun_entry, "exit":fun_exit}
                        metadata[str(fun_name)]["addresses"].append({"address":str(ref.getFromAddress()).lstrip("0"), "owner":str(fun_name) + "_" + str(struct_vars[struct_var])})
                        accessed_vars.add(str(fun_name) + "_" + str(struct_vars[struct_var]))
                    elif owner == "array":
                        addrmetada.update({str(ref.getFromAddress()).lstrip("0"):str(struct_vars[struct_var])})
                        if not str(fun_name) in metadata:
                            metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[], "rsp":adjust_off, "entry":fun_entry, "exit":fun_exit}
                        metadata[str(fun_name)]["addresses"].append({"address":str(ref.getFromAddress()).lstrip("0"), "owner":str(fun_name) + "_" + str(struct_vars[struct_var])})
                        accessed_vars.add(str(fun_name) + "_" + str(struct_vars[struct_var]))
            continue
        except:
            for ref in refmanager.getReferencesTo(variable):
                # checks to avoid the accesses
                if str(ref.getReferenceType()) == "DATA":
                    if owner != "array":
                        continue
                if str(ref.getReferenceType()) == "READ" and owner == "scalar":
                    continue
                if str(ref.getReferenceType()) == "READ" and owner == "pointer":
                    if "MOV" not in getInstructionAt(ref.getFromAddress()).getMnemonicString():
                        continue
                    register = getInstructionAt(ref.getFromAddress()).getRegister(0).getBaseRegister()
                    predictvar(ref.getFromAddress().next(), variable.getName(), register, fun_name, str(fun_name))
                    continue
                addrmetada.update({str(ref.getFromAddress()).lstrip("0"):str(variable.getName())})
                if not str(fun_name) in metadata:
                    metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[], "rsp":adjust_off, "entry":fun_entry, "exit":fun_exit}
                metadata[str(fun_name)]["addresses"].append({"address":str(ref.getFromAddress()).lstrip("0"), "owner":str(fun_name) + "_" + str(variable.getName())})
                accessed_vars.add(str(fun_name) + "_" + str(variable.getName()))
        # get the varibale name/ owner
        varname = variable.getName()
        # size of the variable
        size = variable.getLength()
        if not str(fun_name) in metadata:
            metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[], "rsp":adjust_off, "entry":fun_entry, "exit":fun_exit}
        metadata[str(fun_name)]["variables"].append({"owner":str(fun_name) + "_" + str(varname), "offset":offset + adjust_off, "dtype":str(dtype).replace(" ", ""), "ownertype":owner, "size":size})
        varmetada[str(varname)] = {"offset":offset + adjust_off, "dtype":str(dtype).replace(" ", ""), "owner":owner, "size":size}

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
            if not inst.getNumOperands() == 2 or "MOV" not in inst.getMnemonicString():
                cur = cur.next()
                continue
            if all(x in [str(i.getMnemonic()) for i in inst.getPcode()] for x in ['INT_ADD', 'COPY']):
                # for the store instruction
                if len(inst.getOpObjects(0)) >= 3:
                    for off in offsetvarmetada:
                        if hex(off) in [str(x) for x in inst.getOpObjects(0)]:
                            addrmetada.update({str(cur).lstrip("0"):str(offsetvarmetada[off])})
                            if not str(fun_name) in metadata:
                                metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[], "rsp":adjust_off, "entry":fun_entry, "exit":fun_exit}
                            metadata[str(fun_name)]["addresses"].append({"address":str(cur).lstrip("0"), "owner":str(fun_name) + "_" + str(offsetvarmetada[off])})
                            accessed_vars.add(str(fun_name) + "_" + str(offsetvarmetada[off]))
                # for the load instruction
                if len(inst.getOpObjects(1)) >= 3:
                    for off in offsetvarmetada:
                        if hex(off) in [str(x) for x in inst.getOpObjects(1)]:
                            addrmetada.update({str(cur).lstrip("0"):str(offsetvarmetada[off])})
                            if not str(fun_name) in metadata:
                                metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[], "rsp":adjust_off, "entry":fun_entry, "exit":fun_exit}
                            metadata[str(fun_name)]["addresses"].append({"address":str(cur).lstrip("0"), "owner":str(fun_name) + "_" + str(offsetvarmetada[off])})
                            accessed_vars.add(str(fun_name) + "_" + str(offsetvarmetada[off]))
        cur = cur.next()

# get globals/static symbols
# ignore_symbols = { "_start", "__libc_start_main", "__libc_csu_init", "_init",  "exit",
# "_dl_relocate_static_pie", "_fini", "__libc_csu_fini", "malloc", "calloc", "realloc", "free",
# "gets", "printf", "scanf", "puts", "fgets", ".plt", "atoi", "fopen", "fclose", "__assert_fail",
# "strcmp", "strcpy", "strlen", "getc", "getchar", "putchar", "putc", "strcat", "sprint", "fprintf",
# "setitimer", "pause", "signal", "sigalrm_handler", "strncpy", "memset", "strdup", "wcscpy", "wcslen",
# "shmdt", "shmctl", "shmat", "shmget", "register_tm_clones", "deregister_tm_clones",
# "__do_global_dtors_aux", "relSharedMem", "getSharedMem", "frame_dummy", "getenv", "sleep", "wait", "fork",
# "setjump", "longjump", "_setjmp", "getcwd", "longjmp", "memcpy", "__frame_dummy_init_array_entry", "__lxstat", "__xstat"}
def get_data_symbols():
    # these are the symbols which are defined in the data section
    symbols = set(currentProgram.getSymbolTable().getAllSymbols(True))
    for s in symbols:
        # if str(s) in ignore_symbols:
        #     continue
        # instructions to be referenced from the global variables
        # print(s.getObject().getParent().getLength())
        ref_instructions = [getInstructionAt(x.getFromAddress()) for x in s.getReferences()]
        if ref_instructions and not all(x is None for x in ref_instructions):
            try:
                address = str(s.getAddress()).lstrip("0")
                size = str(s.getObject().getLength())
                # where is this variable? is it in the global namespace or is in the function namespace
                if s.isGlobal():
                    namespace = ".global"
                else:
                    namespace = str(s.getPath()[0])
                dtype = s
                owner = predictownertype(s.getObject().getDataType().getDefaultLabelPrefix())
                # most of the cases fail here, if they don't belong to any instructions
                addresses = [x.getFromAddress() for x in s.getReferences()]
                # predict type
                if s.getObject().getParent():
                    # decide their namespace - it will be same as the their parent function
                    if s.isGlobal():
                        namespace = str(getFunctionContaining(s.getReferences()[0].getFromAddress()).getName())
                    if s.getObject().getParent().isArray():
                        dtype = s.getObject().getParent().getPathName()
                        size = str(s.getObject().getParent().getLength())
                        address = str(s.getObject().getParent().getAddress()).lstrip("0")
                    owner = s.getObject().getParent()
                    owner = predictownertype(owner.getBaseDataType().getDefaultLabelPrefix())
                try:
                    # first variable in a structure
                    for component in s.getObject().getDataType().getDefinedComponents():
                        owner = predictownertype(component.getDataType().getDefaultLabelPrefix())
                        size = str(component.getLength())
                        dtype = str(dtype) + "." + str(component.getFieldName())
                        namespacemetada[str(component.getFieldName())] = {"dtype":str(component.getDataType()).replace(" ", ""), "owner":owner, "size":size}
                        break
                except:
                    pass
                for ref in s.getReferences():
                    if getInstructionAt(x.getFromAddress()) == None:
                        continue
                    if str(ref.getFromAddress()) == "Entry Point":
                        continue
                    fun_name = getFunctionContaining(ref.getFromAddress()).getName()
                    if str(ref.getReferenceType()) == "EXTERNAL":
                        continue
                    if str(ref.getReferenceType()) == "INDIRECTION":
                        # print(dtype)
                        # print(ref.getReferenceType())
                        continue
                    if str(ref.getReferenceType()) == "DATA":
                        continue
                    if str(ref.getReferenceType()) == "READ" and owner == "scalar":
                        continue
                    if str(ref.getReferenceType()) == "READ" and owner == "pointer":
                        if "MOV" not in getInstructionAt(ref.getFromAddress()).getMnemonicString():
                            continue
                        register = getInstructionAt(ref.getFromAddress()).getRegister(0).getBaseRegister()
                        predictvar(ref.getFromAddress(), dtype, register, fun_name, namespace)
                        continue
                    if str(fun_name) not in metadata:
                        metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[], "rsp":adjust_off, "entry":fun_entry, "exit":fun_exit}
                    metadata[str(fun_name)]["addresses"].append({"address":str(ref.getFromAddress()).lstrip("0"), "owner":namespace + "_" + str(dtype)})
                    accessed_vars.add(namespace + "_" + str(dtype))
                if namespace == ".global":
                    # if namespace + "_" + str(dtype) not in accessed_vars:
                    #     continue
                    metadata[".global"].append({"owner":namespace + "_" + str(dtype),"datatype":owner, "address":address, "size":size})
                    continue
                elif str(namespace) not in metadata:
                    metadata[str(namespace)] = {"variables":[], "addresses":[], "namespace":[], "rsp":adjust_off, "entry":fun_entry, "exit":fun_exit}
                metadata[str(namespace)]["namespace"].append({"owner":namespace + "_" + str(dtype),"datatype":owner, "address":address, "size":size})
            except AttributeError:
                pass

# store all functions
functions = set()

ignore_funs = {"__xstat", "__lxstat"}

# get all user defined/called functions
def get_functions(func):
    if func not in functions:
        functions.add(func)
    else:
        return
    # if called functions are present
    # print(getGlobalFunctions(func.getName()))
    if getGlobalFunctions(func.getName()):
        if getGlobalFunctions(func.getName())[0].getCalledFunctions(monitor):
            for child in getGlobalFunctions(func.getName())[0].getCalledFunctions(monitor):
                if str(child) not in ignore_funs:
                    get_functions(child)

get_functions(getGlobalFunctions("main")[0])

for function in functions:
    print(function)
    # print("in")
    # adjust offset
    # this flag is used to adjust the relative variable offset
    adjust_off = 0
    if str(getInstructionAt(function.getEntryPoint())) == "PUSH RBP":
        adjust_off = currentProgram.getLanguage().getLanguageDescription().getSize() >> 3
    # set function entrypoint
    fun_entry = function.getEntryPoint()
    fun_exit = function.getBody().getMaxAddress()
    # apply the decompiler interface analysis
    # storesymbols(function)
    parameters = list(function.getParameters())
    # print(parameters)
    variables = list(function.getLocalVariables())
    # print(variables)
    printvariable(variables, parameters, function.getName())
    predictarrvar(function.getEntryPoint(), function.getName())
    # make placeholder dictionaries empty
    varmetada = {}
    addrmetada = {}

get_data_symbols()

path, file = os.path.split(currentProgram.getExecutablePath())

# if DAT_ in global variable names, then increase their size by 1
# as they are most likely to be strings
for x in metadata[".global"]:
    if int(x["size"])==1 and "DAT_" in x["owner"]:
        x["size"]=str(int(x["size"])+1)

bin = []

metadata[".global"] = sorted(metadata[".global"], key=lambda k: k["address"])
for i in range(len(metadata[".global"])-1):
    own = metadata[".global"][i]["owner"]
    siz = metadata[".global"][i]["size"]
    addr = int(metadata[".global"][i]["address"], 16)
    temp_bin = [(own, addr, siz)]
    addr_range = range(addr, addr+int(metadata[".global"][i]["size"]))
    for j in range(i+1, len(metadata[".global"])-1):
        own_next = metadata[".global"][j]["owner"]
        siz_next = metadata[".global"][j]["size"]
        addr_next = int(metadata[".global"][j]["address"], 16)
        addr_range_next = range(addr_next, addr_next+int(metadata[".global"][j]["size"]))
        if not set(addr_range).isdisjoint(addr_range_next):
            temp_bin.append((own_next, addr_next, siz_next))
    if len(temp_bin) >1:
        found = False
        for item in bin:
            if (own, addr, siz) in item:
                item.extend(temp_bin)
                found = True
        if not found:
            # bin may have duplicates
            bin.append(temp_bin)

# a set of items to be added
items_to_add = []
for own in metadata[".global"][:]:
    # print(own)
    for item in bin:
        if (own["owner"],int(own["address"], 16), own["size"]) in item:
            # print(item[0][-2], item[-1][-2]+int(item[-1][-1])-1)
            temp = {"owner":item[0][0], "address":hex(item[0][-2]).split('x')[-1], "size":str(item[-1][-2]+int(item[-1][-1])-item[0][-2]), "datatype":"scalar"}
            if not temp in items_to_add:
                items_to_add.append(temp)
            metadata[".global"].remove(own)

# add aggregated types back to the global list
metadata[".global"].extend(items_to_add)

# Now create a file to render it to the pintool
with open(os.path.join(path, os.path.splitext(file)[0]) + "-volatile.text", "w") as f:
    count = len(metadata) - 1
    f.write("{}\n".format(count))
    for k,v in metadata.items():
        if k == ".global":
            continue
        f.write("{}\n".format(k))
        f.write("{}\n".format(v["rsp"]))
        f.write("{}\n".format(str(v["entry"]).lstrip("0")))
        f.write("{}\n".format(str(v["exit"]).lstrip("0")))
        f.write("{}\n".format("addresses"))
        for add in [dict(t) for t in {tuple(d.items()) for d in v["addresses"]}]:
            f.write("{} ".format(add["address"]))
            f.write("{}\n".format(add["owner"]))
        f.write("\n")
        f.write("{}\n".format("locals"))
        for var in v["variables"]:
            f.write("{} {} {} {}\n".format(var["offset"], var["ownertype"], var["owner"], var["size"]))
        f.write("\n")
        f.write("{}\n".format("namespace"))
        for var in v["namespace"]:
            f.write("{} {} {} {}\n".format(str(int(var["address"], 16)), var["datatype"], var["owner"], var["size"]))
        f.write("\n")
    f.write(".global\n")
    for var in metadata[".global"]:
        f.write("{} {} {} {}\n".format(str(int(var["address"], 16)), var["datatype"], var["owner"], var["size"]))
    f.write("\n")
