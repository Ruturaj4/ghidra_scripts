import sys
import json
import idc
import idautils
import idaapi
import ida_struct
import ida_typeinf
import ida_frame
import ida_funcs
import ida_bytes
import ida_hexrays
# wait for auto-analysis to complete
idc.auto_wait()

#set decompiler
decompiler = 0
if decompiler:
    ida_hexrays.init_hexrays_plugin()

class Instruction:
    def __init__(self, item, ea):
        self.item = item
        self.ea = ea
    def get_address(self):
        return format(self.item, 'x')
    def get_disassembly(self):
        return idc.GetDisasm(self.item)
    def get_operand(self, n):
        return idc.print_operand(self.item,n)
    def get_operand_type(self, n):
        return idc.get_operand_type(self.item, n)
    def get_operand_value(self, n):
        return idc.get_operand_value(self.item, n)
    def get_decoded(self):
        return idautils.DecodeInstruction(self.item)
    def get_mnemonic(self):
        return ida_ua.ua_mnem(self.item)

class Local_variable:
    def __init__(self, mem, stack_size, ea):
        self.mem = mem
        self.stack_size = stack_size
        self.ea = ea
    def get_offset(self):
        return -self.stack_size + self.mem.get_soff()
    def get_size(self):
        return ida_struct.get_member_size(self.mem)
    def get_name(self):
        return idc.get_func_name(self.ea)+"_"+ida_struct.get_member_name(self.mem.id)
    # name including parent name
    def get_full_name(self):
        return ida_struct.get_member_fullname(self.mem.id)
    def get_misc(self):
        return self.mem.id
    def get_type(self):
        tif = ida_typeinf.tinfo_t()
        success = ida_struct.get_member_tinfo(tif, self.mem)
        return tif.get_realtype()
    @property
    def is_array_type(self):
        tif = ida_typeinf.tinfo_t()
        success = ida_struct.get_member_tinfo(tif, self.mem)
        return ida_typeinf.is_type_array(tif.get_realtype())
    def get_ownertype(self):
        tif = ida_typeinf.tinfo_t()
        success = ida_struct.get_member_tinfo(tif, self.mem)
        # if type information is available in Ida analysis
        if success:
            if ida_typeinf.is_type_ptr_or_array(tif.get_realtype()):
                return "pointer"
            else:
                return "scalar"
        # return type scalar by default
        else: return "scalar"
    def get_refs(self):
        xrefs = ida_frame.xreflist_t()
        ida_frame.build_stkvar_xrefs(xrefs, ida_funcs.get_func(self.ea), self.mem)
        return xrefs
    @property
    def is_structure(self):
        return True if ida_struct.get_sptr(self.mem) else False
    # def get_member_ids(self, sid):
    #     offset = 0
    #     # detect upto 10 structure items
    #     i = 10
    #     while i:
    #         mid = idc.get_member_id(sid, offset)
    #         if mid != -1:
    #             yield mid
    #         offset = idc.get_next_offset(sid, offset)
    #         i -= 1
    # def get_member_xrefs(self):
    #     sid = ida_struct.get_sptr(self.mem).id
    #     for mid in self.get_member_ids(sid):
    #         name = ida_struct.get_member_name(mid)
    #         print(name)
    #         for xref in idautils.XrefsTo(mid):
    #             yield xref.frm
    def get_struct_members(self):
        struct_members = []
        sid = ida_struct.get_sptr(self.mem).id
        for mem in ida_struct.get_struc(sid).members:
            struct_members.append(Struct_members(mem, self.stack_size, self.ea))
        return struct_members

class Struct_members(Local_variable):
    def get_refs(self):
        for xref in idautils.XrefsTo(self.mem.id):
            yield(xref)
    def get_offset(self):
        return self.mem.get_soff()
# select functions for analysis
functions = set()
ignore_funs = ["printf", ".printf"]
# get function callee information
# def handle_function(func_start):
#     for h in idautils.FuncItems(func_start):
#         for r in idautils.XrefsFrom(h, 0):
#             print(r.type)
#             print(get_func_name(h), "--calls-->", get_func_name(r.to))

# def generate_graph():
#     callees = dict()
#     # loop through all functions
#     for function_ea in idautils.Functions():
#         # handle_function(function_ea)
#         f_name = idc.get_func_name(function_ea)
# 		# For each of the incoming references
#         for ref_ea in idautils.CodeRefsTo(function_ea, 0):
#             # Get the name of the referring function
#             caller_name = idc.get_func_name(ref_ea)
#             # Add the current function to the list of functions
#             # called by the referring function
#             callees[str(caller_name)] = callees.get(str(caller_name), set())
#             callees[str(caller_name)].add(str(f_name))
#     return callees

def generate_graph():
    callees = {}
    # loop through all functions
    for function_ea in idautils.Functions():
        f_name = idc.get_func_name(function_ea)
        callees[str(f_name)] = set()
        for h in idautils.FuncItems(function_ea):
            for r in idautils.XrefsFrom(h, 0):
                caller_name = idc.get_func_name(r.to)
                callees[str(f_name)].add(str(caller_name))
    return callees

function_graph = generate_graph()
# print(function_graph)
# get all user defined/called functions
def get_functions(func):
    if func not in functions:
        functions.add(func)
    else:
        return
    # if called functions are present
    if func in function_graph:
        if function_graph[func]:
            for child in function_graph[func]:
                if child not in ignore_funs:
                    get_functions(child)
get_functions("main")
print(functions)
# local variable information
def get_local_vars(ea, stack_size):
    # can be used to get member size, type, etc.
    local_variables = []
    for mem in ida_struct.get_struc(idc.get_frame_id(ea)).members:
        local_variables.append(Local_variable(mem, stack_size, ea))
    return local_variables

# instruction_map maps addresses to thier owners
instruction_map = {}
# global metadata
metadata = {".global":[]}

def is_user_name(ea):
  f = idc.get_full_flags(ea)
  return idc.hasUserName(f)
# get global or static symbols
def get_data_symbols():
    idata_seg_selector = idc.selector_by_name(".bss")
    idata_seg_startea = idc.get_segm_by_sel(idata_seg_selector)
    idata_seg_endea = idc.get_segm_end(idata_seg_startea)
    for seg_ea in range(idata_seg_startea, idata_seg_endea):
        if idc.get_name(seg_ea):
            address = format(seg_ea, 'x')
            name = ".global"+"_"+idc.get_name(seg_ea)
            size = idc.get_item_size(seg_ea)
            dtype = ida_bytes.get_data_elsize(seg_ea, idc.get_full_flags(seg_ea))
            if size == dtype == 8:
                ownertype = "pointer"
            elif size == dtype != 8:
                ownertype = "scalar"
            elif size > dtype:
                ownertype = "array"
            else:
                continue
            for xref in idautils.XrefsTo(seg_ea):
                # print(format(xref.frm, 'x'))
                function = idc.get_func_name(xref.frm)
                # print(function)
                if function not in functions:
                    continue
                # print(function)
                if str(function) not in instruction_map:
                    instruction_map[str(function)] = {}
                instruction_map[str(function)][format(xref.frm, 'x')]=name,ownertype
                # print("Found a cross reference {}: from {:x} to variable {}".format(xref, xref.frm, name))
            metadata[".global"].append({"owner":name,"datatype":ownertype, "address":address, "size":size})

# save variable information with instruction mappings
def printvariable(local_variables, function):
    if str(function) not in instruction_map:
        instruction_map[str(function)] = {}
    for var in local_variables:
        # todo: structure vars
        name = var.get_name()
        # print(name)
        # ignore special names assigned by ida
        if name == str(function) + "_" + " r" or name == str(function) + "_" + " s":
            continue
        offset = var.get_offset()
        type = var.get_type()
        ownertype = var.get_ownertype()
        size = var.get_size()
        if decompiler:
            if offset in hexrays_types[str(function)]:
                size, ownertype = hexrays_types[str(function)][offset]
        # print(name)
        if var.is_structure and not var.is_array_type:
            # for xref in var.get_member_xrefs():
            #     print(format(xref, 'x'))
            for member in var.get_struct_members():
                name = var.get_name()+"_"+member.get_name()
                # print(name)
                offset = var.get_offset() + member.get_offset()
                # print(offset)
                type = member.get_type()
                ownertype = member.get_ownertype()
                # print(ownertype)
                size = member.get_size()
                # print(size)
                if decompiler:
                    if offset in hexrays_types[str(function)]:
                        size, ownertype = hexrays_types[str(function)][offset]
                for ref in member.get_refs():
                    # print(format(ref.frm, 'x'))
                    instruction_map[str(function)][format(ref.frm, 'x')]=name,ownertype
                metadata[str(function)]["variables"].append({"owner":name, \
                "offset":offset, "dtype":str(type), "ownertype":str(ownertype), "size":size})
            continue
        for ref in var.get_refs():
            # print(format(ref.ea, 'x'))
            instruction_map[str(function)][format(ref.ea, 'x')]=name,ownertype
        metadata[str(function)]["variables"].append({"owner":name, \
        "offset":offset, "dtype":str(type), "ownertype":str(ownertype), "size":size})

def printowners(block_entry, block_exit, function, instructions):
    print(format(block_entry, 'x'), format(block_exit, 'x'))
    cur = block_entry
    # a dic of registers and pointers to be tracked
    regs = {}
    # stay in current block
    while cur:
        if cur>=block_exit:
            break
        if cur in instructions:
            ins = instructions[cur]
            # ret if return instruction
            if "retn" in str(ins.get_mnemonic()):
                break
            print("{}: {}".format(ins.get_address(), ins.get_disassembly()))
            owner = ""
            if format(cur, 'x') in instruction_map[str(function)]:
                owner = instruction_map[str(function)][format(cur, 'x')][0]
                ownertype = instruction_map[str(function)][format(cur, 'x')][1]
                metadata[str(function)]["addresses"].append({"address":str(format(cur, 'x')), "owner":str(owner)})
            # move instruction
            if "mov" in str(ins.get_mnemonic()):
                # print(ins.get_operand(0))
                # print(ins.get_operand(1))
                # detect 'mov reg reg' instruction
                if ins.get_operand_type(0) == o_reg:
                    if ins.get_operand_type(1) == o_reg:
                        if owner:
                            regs[idaapi.get_reg_name(ins.get_operand_value(0), 8)] = owner
                            pass
                        else:
                            if idaapi.get_reg_name(ins.get_operand_value(1), 8) in regs:
                                regs[idaapi.get_reg_name(ins.get_operand_value(0), 8)] = \
                                regs[idaapi.get_reg_name(ins.get_operand_value(1), 8)]
                    # track register loads - 'mov reg mem'
                    elif ins.get_operand_type(1) == o_displ:
                        if owner:
                            # if the register is 64-bit e.g. rax
                            # mov reg==64 mem
                            if ins.get_decoded().Op1.dtype == idaapi.dt_qword:
                                # transfer the owner
                                regs[idaapi.get_reg_name(ins.get_operand_value(0), 8)] = owner
                                # if the owner is present then remove this instruction from our final file
                                metadata[str(function)]["addresses"] = [x for x in metadata[str(function)]\
                                ["addresses"] if x["address"] != str(format(cur, 'x'))]
                        else:
                            # if arithmentic pattern is not used then just continue
                            if "rbp" in ins.get_operand(1) or "rsp" in ins.get_operand(1):
                                # number of operand objects are less than 3
                                # uncomment this if using prediction for variables
                                # if not ins.get_decoded().Op2.specflag1:
                                if ins.get_decoded().Op1.dtype != idaapi.dt_qword:
                                    regs.pop(idaapi.get_reg_name(ins.get_operand_value(0), 8), None)
                                cur += 1
                                continue
                            # if not ins.get_decoded().Op2.specflag1:
                            if idaapi.get_reg_name(ins.get_decoded().Op2.phrase, 8) in regs:
                                metadata[str(function)]["addresses"].append({"address":str(format(cur, 'x')),\
                                "owner":str(regs[idaapi.get_reg_name(ins.get_decoded().Op2.phrase, 8)])})
                                # remove the register from the pointer map
                                # as the register may no longer contain a pointer
                                regs.pop(idaapi.get_reg_name(ins.get_operand_value(0), 8), None)
                                cur += 1
                                continue
                            # if register arithmetic with op1 objects greater than equal to 3 is used then
                            # we may be able to predict the owner if not predicted already
                            # if ins.get_decoded().Op2.specflag1:
                            #     for v in metadata[str(function)]["variables"]:
                            #         print(hex(v["offset"]))
                    # track register loads - 'mov reg imm'
                    elif ins.get_operand_type(1) == o_imm:
                        if idaapi.get_reg_name(ins.get_operand_value(0), 8) in regs:
                            regs.pop(idaapi.get_reg_name(ins.get_operand_value(0), 8), None)
                else:
                    if owner:
                        # if the owner is scalar then remove this instruction from our final file
                        if ownertype == "scalar":
                            metadata[str(function)]["addresses"] = [x for x in metadata[str(function)]\
                            ["addresses"] if x["address"] != str(format(cur, 'x'))]
                    else:
                        # track register loads - 'mov reg imm'
                        if idaapi.get_reg_name(ins.get_decoded().Op1.phrase, 8) in regs:
                            metadata[str(function)]["addresses"].append({"address":str(format(cur, 'x')),\
                            "owner":str(regs[idaapi.get_reg_name(ins.get_decoded().Op1.phrase, 8)])})
                            # remove the register from the pointer map
                            # as the register may no longer contain a pointer
                            cur += 1
                            continue
            # fld instruction
            if "fld" in str(ins.get_mnemonic()):
                # only consider instruction where access is used
                if ins.get_operand(1):
                    if idaapi.get_reg_name(ins.get_decoded().Op2.phrase, 8) in regs:
                        metadata[str(function)]["addresses"].append({"address":str(format(cur, 'x')),\
                        "owner":str(regs[idaapi.get_reg_name(ins.get_decoded().Op2.phrase, 8)])})
            # lea instruction
            if "lea" in str(ins.get_mnemonic()):
                if owner:
                    regs[idaapi.get_reg_name(ins.get_operand_value(0), 8)] = owner
                else:
                    if idaapi.get_reg_name(ins.get_decoded().Op2.phrase, 8) in regs:
                        regs[idaapi.get_reg_name(ins.get_operand_value(0), 8)] =\
                        idaapi.get_reg_name(ins.get_decoded().Op2.phrase, 8)
            # call instruction
            if "call" in str(ins.get_mnemonic()):
                # void the registers as function calling convention may affect registers
                regs = {}
        cur += 1

hexrays_types = {}

# get hex rays variables
def get_hexrays_vars(ea, stack_size):
    # can be used to get member size, type, etc.
    hexrays_types[idc.get_func_name(ea)] = {}
    for var in ida_hexrays.decompile(ea).get_lvars():
        if not var.name:
            continue
        if var.tif.is_ptr_or_array and var.width>=8:
            ownertype = "pointer"
        else:
            ownertype = "scalar"
        # print(dir(var.tif))
        offset = -stack_size + var.get_stkoff()
        hexrays_types[idc.get_func_name(ea)][offset] = var.width, ownertype
        # print(dir(var))

# get global variables
get_data_symbols()

for ea in idautils.Functions():
    if not str(idc.get_func_name(ea)) in functions:
        continue
        # print(dir(va))
    # print(ida_hexrays.decompile(ea).arguments)
    # check if library function
    if not idc.get_segm_name(ea) == ".text":
        continue
    if idc.get_func_flags(ea) & FUNC_LIB:
        continue
    if decompiler:
        get_hexrays_vars(ea, idc.get_func_attr(ea, idc.FUNCATTR_FRSIZE))
    # function name
    fun_name = idc.get_func_name(ea)
    # print(dir(idc))
    # function stack size and boundaries
    stack_size = idc.get_func_attr(ea, idc.FUNCATTR_FRSIZE)
    fun_entry = format(idc.get_func_attr(ea, FUNCATTR_START), 'x')
    fun_exit = format(idc.get_func_attr(ea, FUNCATTR_END), 'x')
    # instructions
    instructions = {item:Instruction(item, ea) for item in idautils.FuncItems(ea)}

    # check if rbp or rsp relative addressing
    adjust_off = 0
    if str(instructions[ea].get_disassembly()) == "push    rbp":
        adjust_off = 8
    if str(fun_name) in metadata:
        # metadata[str(fun_name)]["rsp"] = str(adjust_off)
        metadata[str(fun_name)]["entry"] = str(fun_entry).lstrip("0")
        metadata[str(fun_name)]["exit"] = str(fun_exit).lstrip("0")
    else:
        # todo: add "rsp":str(adjust_off),
        metadata[str(fun_name)] = {"variables":[], "addresses":[], "namespace":[], \
        "rsp":str(adjust_off), "entry":str(fun_entry).lstrip("0"), "exit":str(fun_exit).lstrip("0")}

    # stack variables
    local_variables = get_local_vars(ea, stack_size)
    printvariable(local_variables, fun_name)
    # iterate through static building blocks
    function = idaapi.get_func(ea)
    flowchart = idaapi.FlowChart(function)
    # print("Function starting at 0x%x consists of %d basic blocks" % (function.start_ea, flowchart.size))
    for bb in flowchart:
        printowners(bb.start_ea ,bb.end_ea, fun_name, instructions)

print(metadata)
path, file = os.path.split(idaapi.get_input_file_path())

# Now create a file to render it to the pintool
with open(os.path.join(path, os.path.splitext(file)[0]) + ".idatext", "w") as f:
    count = len(metadata) - 1
    f.write("{}\n".format(count))
    for k,v in metadata.items():
        if k == ".global":
            continue
        f.write("{}\n".format(k))
        f.write("{}\n".format(v["rsp"]))
        f.write("{}\n".format(v["entry"]))
        f.write("{}\n".format(v["exit"]))
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

with open(os.path.join(path, os.path.splitext(file)[0])+ ".idajson", "w") as f:
    json.dump(metadata, f)
idc.qexit(0)
