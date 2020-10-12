import idc
import idautils

functions = idautils.Functions()
f = open(idc.ARGV[1], 'a') if len(idc.ARGV) > 1 else sys.stdout
log = f.write

# log current file path
log(idc.get_input_file_path() + '\n')

# wait for auto-analysis to complete
idc.auto_wait()

for f in functions:
    log(idc.get_func_name(f) + "\n")
    print idc.get_func_name(f)

idc.qexit(4)
