# ClassInformer python
# Nicolas Guigo / NCC Group
# Tyler Colgan / NCC Group
# 03/2017

import idaapi
from idc import *

idaapi.require("utils")
idaapi.require("msvc")
idaapi.require("gcc")
idaapi.require("classdiagram")
from idaapi import auto_is_ok
from msvc import run_msvc
from gcc import run_gcc
from classdiagram import ClassDiagram

def show_classes(classes):
    c = ClassDiagram("Class Diagram", classes)
    c.Show()

def isGcc():
    gcc_info = find_text(0x0, SEARCH_CASE|SEARCH_DOWN, 0, 0, "N10__cxxabiv117__class_type_infoE")
    return gcc_info != BADADDR

def main():
    print("Starting ClassInformerPython")
    if auto_is_ok():
        classes = run_gcc()
        #classes = run_gcc() if isGcc() else run_msvc()
        print(classes)
        show_classes(classes)
    else:
        print("Take it easy, man")
    print("Done")

if __name__ == '__main__':
    main()