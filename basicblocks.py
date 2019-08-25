# credits for code logic
# AndrewFasano/VisualizingFuzzerCoverage - github
from ghidra.program.model.block import BasicBlockModel

blockiterator = BasicBlockModel(currentProgram).getCodeBlocks(monitor)
# dictionary contains basic block information
functions = {}

def add_block(function, block):
    if function not in functions:
         functions[function] = []
    functions[function].append(block)

# For each block, look through the function list until we find a match
# This is terribly inefficient (O(N^2))

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

print(functions)
