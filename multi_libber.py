#!/usr/bin/python3

import sys
import ar # https://github.com/vidstige/ar
import os
import argparse
import lief
from lief.ELF import *
import tempfile
import shutil

def get_symbols_to_patch(obj, syms_to_patch):
    for symbol in obj.symbols:
        if symbol.exported \
                or symbol.is_function \
                and symbol.is_static \
                and not symbol.is_variable \
                and symbol.binding in [SYMBOL_BINDINGS.GLOBAL, SYMBOL_BINDINGS.WEAK]:
            if not (symbol.name in syms_to_patch):
                syms_to_patch += [symbol.name]


def apply_patch(obj, syms_to_patch, prefix):
    for symbol in obj.symbols:
        if symbol.name in syms_to_patch:
            symbol.name = prefix + symbol.name


def patch_objs(objs, prefix, patch_list_file, patching, syms_to_patch):
    print("retrieving symbols to patch")
    if patching:
        with open(patch_list_file, "r") as patch_list:
            syms_to_patch = patch_list.read().split("\n")[:-1]
    else:
        for obj in objs:
            get_symbols_to_patch(obj, syms_to_patch)

    print("applying symbol prefix patch")
    for obj in objs:
        apply_patch(obj, syms_to_patch, prefix)

    print("writing result")
    for obj in objs:
        obj.write(obj.name)


def write_patch_list(patch_list_file, syms_to_patch):
    with open(patch_list_file, "a") as patch_list:
        patch_list.write("\n".join(syms_to_patch)+"\n")


def main():
    # Parse the arguments
    parser = argparse.ArgumentParser("")
    parser.add_argument("input_file", help="input_file to relocate")
    parser.add_argument("output_file", help="output_file file")
    parser.add_argument("patch_list_file", help="file with a list of function to patch or that got patched, will not overwrite")
    parser.add_argument("--patch", default=False, const=True, action="store_const", help="use this to use the function list to patch another archive")
    parser.add_argument("--prefix", default="__traced_", help="input_file to relocate")
    args = parser.parse_args()

    input_file = os.path.abspath(args.input_file)
    output_file = os.path.abspath(args.output_file)
    patch_list_file = os.path.abspath(args.patch_list_file)

    syms_to_patch = []

    # parse and patch a single object file
    if input_file.endswith(".o"):
        # shutil.copy(input_file, output_file)
        obj = lief.parse(input_file)
        obj.name = output_file
        patch_objs([obj], args.prefix, patch_list_file, args.patch, syms_to_patch)

    # parse and patch an archive of object files
    elif input_file.endswith(".a"):
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)

            # retrieve the object files
            with open(input_file, "rb") as f:
                archive = ar.Archive(f)
                i = 0
                for entry in archive:
                    stream = entry.get_stream(f)
                    # we need to add an integer prefix because ar archives can have
                    # 2 entries with the same name
                    with open(str(i)+entry.name, "wb") as fo:
                        fo.write(stream.read())
                    i += 1

            print("parsing obj files")
            objs_filename = os.listdir()
            objs = []
            for obj_filename in objs_filename:
                objs.append(lief.parse(obj_filename))

            patch_objs(objs, args.prefix, patch_list_file, args.patch, syms_to_patch)

            # rebuild the archive
            os.system("ar rc "+output_file+" "+" ".join(objs_filename))
            os.system("ranlib "+output_file)
        os.chdir(cwd)

    # write the patch list
    if not args.patch:
        write_patch_list(patch_list_file, syms_to_patch)


if __name__ == "__main__":
    main()
