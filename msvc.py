from idaapi import get_struc_id, BADADDR, del_struc, get_struc, add_struc, add_struc_member, FF_DATA, FF_DWRD, FF_0OFF, get_struc_size, FF_ASCI, do_unknown_range, DOUNK_DELNAMES, doStruct, get_member_by_name, get_32bit, get_ascii_contents, demangle_name, doDwrd, op_offset
from idc import *
from idc_bc695 import *

from utils import utils
u = utils()

classes = {}

class RTTIStruc:
    tid = 0
    struc = 0
    size = 0

def strip(name):
    if name.startswith("class ") and name.endswith("`RTTI Type Descriptor'"):
        return name[6:-23]
    elif name.startswith("struct ") and name.endswith("`RTTI Type Descriptor'"):
        return name[7:-23]
    else:
        return name

class RTTICompleteObjectLocator(RTTIStruc):

    # Init class statics
    msid = get_struc_id("RTTICompleteObjectLocator")
    if msid != BADADDR:
        del_struc(msid)
    msid = add_struc(0xFFFFFFFF, "RTTICompleteObjectLocator", False)
    add_struc_member(msid, "signature", BADADDR, FF_DATA|FF_DWRD, -1, 4)
    add_struc_member(msid, "offset", BADADDR, FF_DATA|FF_DWRD, -1, 4)
    add_struc_member(msid, "cdOffset", BADADDR, FF_DATA|FF_DWRD, -1, 4)
    add_struc_member(msid, "pTypeDescriptor", BADADDR, FF_DATA|FF_DWRD|FF_0OFF, u.mt_rva().tid, 4)
    add_struc_member(msid, "pClassDescriptor", BADADDR, FF_DATA|FF_DWRD|FF_0OFF, u.mt_rva().tid, 4)
    if u.x64:
        add_struc_member(msid, "pSelf", BADADDR, FF_DATA|FF_DWRD|FF_0OFF, u.mt_rva().tid, 4)
    tid = msid
    struc = get_struc(tid)
    size = get_struc_size(tid)
    print("Completed Registering RTTICompleteObjectLocator")

    def __init__(self, ea, vtable):
        do_unknown_range(ea, self.size, DOUNK_DELNAMES)
        if doStruct(ea, self.size, self.tid):
            # Get adress of type descriptor from CompleteLocator
            print("Complete Object Locator at: 0x%x" % ea)
            offset = get_member_by_name(self.struc, "pTypeDescriptor").soff
            typeDescriptor = get_32bit(ea+offset) + u.x64_imagebase()
            print("Looking for type Descriptor at: 0x%x" % typeDescriptor)
            rtd = RTTITypeDescriptor(typeDescriptor)
            if rtd.class_name:
                print("Type Descriptor at: 0x%x" % typeDescriptor)
                offset = get_member_by_name(self.struc, "pClassDescriptor").soff
                classHierarchyDes = get_32bit(ea+offset) + u.x64_imagebase()
                rchd = RTTIClassHierarchyDescriptor(classHierarchyDes)
                # filter out None entries
                rchd.bases = filter(lambda x: x, rchd.bases)
                classes[strip(rtd.class_name)] = [strip(b) for b in rchd.bases]
                MakeNameEx(vtable, "vtable__" + strip(rtd.class_name), SN_NOWARN)
            else:
                # if the RTTITypeDescriptor doesn't have a valid name for us to
                # read, then this wasn't a valid RTTICompleteObjectLocator
                MakeUnknown(ea, self.size, DOUNK_SIMPLE)

class RTTITypeDescriptor(RTTIStruc):
    class_name = None

    msid = get_struc_id("RTTITypeDescriptor")
    if msid != BADADDR:
        del_struc(msid)
    msid = add_struc(0xFFFFFFFF, "RTTITypeDescriptor", False)
    add_struc_member(msid, "pVFTable", BADADDR, FF_DATA|u.PTR_TYPE|FF_0OFF, u.mt_address().tid, u.PTR_SIZE)
    add_struc_member(msid, "spare", BADADDR, FF_DATA|u.PTR_TYPE, -1, u.PTR_SIZE)
    add_struc_member(msid, "name", BADADDR, FF_DATA|FF_ASCI, u.mt_ascii().tid, 0)
    tid = msid
    struc = get_struc(tid)
    size = get_struc_size(tid)
    print("Completed Registering RTTITypeDescriptor")

    def __init__(self, ea):
        name = ea + get_member_by_name(get_struc(self.tid), "name").soff
        strlen = u.get_strlen(name)
        if strlen is None:
            # not a real vtable
            return
        self.size = self.size + strlen
        mangled = get_ascii_contents(name, strlen, 0)
        if mangled is None:
            # not a real function name
            return
        print("Mangled: " + mangled)
        demangled = demangle_name('??_R0' + mangled[1:] , 0)
        if demangled:
            do_unknown_range(ea, self.size, DOUNK_DELNAMES)
            if doStruct(ea, self.size, self.tid):
                print("  Made td at 0x%x: %s" % (ea, demangled))
                self.class_name = demangled
                return
        print("  FAIL :(")
        return

class RTTIClassHierarchyDescriptor(RTTIStruc):
    bases = None

    msid = get_struc_id("RTTIClassHierarchyDescriptor")
    if msid != BADADDR:
        del_struc(msid)
    msid = add_struc(0xFFFFFFFF, "RTTIClassHierarchyDescriptor", False)
    add_struc_member(msid, "signature", BADADDR, FF_DWRD|FF_DATA, -1, 4)
    add_struc_member(msid, "attribute", BADADDR, FF_DWRD|FF_DATA, -1, 4)
    add_struc_member(msid, "numBaseClasses", BADADDR, FF_DWRD|FF_DATA, -1, 4)
    add_struc_member(msid, "pBaseClassArray", BADADDR, FF_DATA|FF_DWRD|FF_0OFF, u.mt_rva().tid, 4)
    tid = msid
    struc = get_struc(tid)
    print("Completed Registering RTTIClassHierarchyDescriptor")

    def __init__(self, ea):
        print("Processing Class Hierarchy Descriptor at 0x%x" % ea)
        do_unknown_range(ea, get_struc_size(self.tid), DOUNK_DELNAMES)
        if doStruct(ea, get_struc_size(self.tid), self.tid):
            baseClasses = get_32bit(ea+get_member_by_name(get_struc(self.tid), "pBaseClassArray").soff) + u.x64_imagebase()
            nb_classes = get_32bit(ea+get_member_by_name(get_struc(self.tid), "numBaseClasses").soff)
            print("Baseclasses array at 0x%x" % baseClasses)
            # Skip the first base class as it is itself (could check)
            self.bases = []
            for i in range(1, nb_classes):
                baseClass = get_32bit(baseClasses+i*4) + u.x64_imagebase()
                print("base class 0x%x" % baseClass)
                doDwrd(baseClasses+i*4, 4)
                op_offset(baseClasses+i*4, -1, u.REF_OFF|REFINFO_RVA, -1, 0, 0)
                doStruct(baseClass, RTTIBaseClassDescriptor.size, RTTIBaseClassDescriptor.tid)
                typeDescriptor = get_32bit(baseClass) + u.x64_imagebase()
                self.bases.append(RTTITypeDescriptor(typeDescriptor).class_name)

class RTTIBaseClassDescriptor(RTTIStruc):
    msid = get_struc_id("RTTIBaseClassDescriptor")
    if msid != BADADDR:
        del_struc(msid)
    msid = add_struc(0xFFFFFFFF, "RTTIBaseClassDescriptor", False)
    add_struc_member(msid, "pTypeDescriptor", BADADDR, FF_DATA|FF_DWRD|FF_0OFF, u.mt_rva().tid, 4)
    add_struc_member(msid, "numContainerBases", BADADDR, FF_DWRD|FF_DATA, -1, 4)
    add_struc_member(msid, "PMD", BADADDR, FF_DATA|FF_DWRD|FF_0OFF, u.mt_rva().tid, 4)
    add_struc_member(msid, "attributes", BADADDR, FF_DWRD|FF_DATA, -1, 4)
    tid = msid
    struc = get_struc(tid)
    size = get_struc_size(tid)
    print("Completed Registering RTTIBaseClassDescriptor")

def run_msvc():
    start = u.rdata.startEA
    end = u.rdata.endEA
    rdata_size = end-start
    for offset in range(0, rdata_size-u.PTR_SIZE, u.PTR_SIZE):
        vtable = start+offset
        if u.isVtable(vtable):
            print("vtable at : " + hex(vtable)[:-1])
            col = u.get_ptr(vtable-u.PTR_SIZE)
            if u.within(col, u.valid_ranges):
                rcol = RTTICompleteObjectLocator(col, vtable)
    u.add_missing_classes(classes)
    return classes
