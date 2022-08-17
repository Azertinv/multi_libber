#!/usr/bin/python3

import sys
import os
import argparse
import lief
from lief.ELF import *
import tempfile
from IPython import embed

def main():
    # Parse the arguments
    parser = argparse.ArgumentParser("")
    parser.add_argument("library", help="library to relocate")
    parser.add_argument("output", help="output file")
    parser.add_argument("function_list", help="file with a list of function to patch or that got patched, will not overwrite")
    parser.add_argument("--patch", default=False, const=True, action="store_const", help="use this to use the function list to patch another archive")
    parser.add_argument("--prefix", default="__traced_", help="library to relocate")
    args = parser.parse_args()

    library = os.path.abspath(args.library)
    output = os.path.abspath(args.output)
    function_list = os.path.abspath(args.function_list)

    # Parse the library
    if library.endswith(".a"):
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            os.system("ar x "+library)

            # parse all the object files
            objs = []
            for obj_filename in os.listdir():
                objs.append(lief.parse(obj_filename))

            # retrieve all the symbols that needs patching
            functions = []
            if args.patch:
                with open(function_list, "r") as fn_list:
                    functions = fn_list.readlines().split("\n")[:-1]
            else:
                for obj in objs:
                    for symbol in obj.symbols:
                        # take every exported functions
                        if symbol.is_function and symbol.binding == SYMBOL_BINDINGS.GLOBAL:
                            if not (symbol.name in functions):
                                functions += [symbol.name]

            # patch all the symbols in the archive
            for obj in objs:
                for symbol in obj.symbols:
                    if symbol.name in functions:
                        symbol.name = args.prefix + symbol.name

            # write the result to disk
            for obj in objs:
                obj.write(obj.name)

            # rebuild the archive
            os.system("ar rc "+output+" "+" ".join(os.listdir()))
            os.system("ranlib "+output)

            # write the function list
            if not args.patch:
                with open(function_list, "a") as fn_list:
                    fn_list.write("\n".join(functions)+"\n")

        os.chdir(cwd)

if __name__ == "__main__":
    main()
