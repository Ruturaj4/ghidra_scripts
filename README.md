# Ghidra Starter scripts

This repository presents small ghidra scripts (python 2.7), which can be used as starter scripts or code snippets, gadgets in bigger projects. These scripts are written in Python 2.7, but converting them into Java should be a bigger task (as the api is same).

### Before getting started
[This](https://ghidra.re/ghidra_docs/analyzeHeadlessREADME.html) document explains in depth about how to use `analyzeHeadless` which is being shipped with ghidra. This is needed to run ghidra in command-line mode (i.e. gui mode is not needed to run the scripts). You can simply use:

`./analyzeHeadless ghidra-project-directory -import binary-file -postscript yourpythonscript`

to run your script say, `yourpythonscript.py`.

### Scripts

* #### [Function List](https://github.com/Ruturaj4/ghidra_scripts/blob/master/function_list.py)
  Prints the list of all the functions used in the binary.

* #### [Decompiled Functions](https://github.com/Ruturaj4/ghidra_scripts/blob/master/decompiled_functions.py)
  Prints decompiled functions
  
* #### [Basic Blocks](https://github.com/Ruturaj4/ghidra_scripts/blob/master/basicblocks.py)
  Calculated and prints basic static basic bloacks

### Final comments

Feel free to fork and support this repo (i.e. you can commit more such scripts), if you really like the idea.
