# Modified from GCC RTTI parsing code originally written by Igor Skochinsky.
# See http://www.hexblog.com/?p=704 for the original version of his code.

import idaapi
from idaapi import BADADDR
from idc import *
from idc_bc695 import *

from utils import utils
u = utils()

all_classes = {}

ti_names = [
 "St9type_info",
 "N10__cxxabiv117__class_type_infoE",
 "N10__cxxabiv120__si_class_type_infoE",
 "N10__cxxabiv121__vmi_class_type_infoE",
]

TI_TINFO = 0
TI_CTINFO = 1
TI_SICTINFO = 2
TI_VMICTINFO = 3

class BaseClass:
    def __init__(self, ti, offset, flags):
        self.ti = ti
        self.offset = offset
        self.flags = flags

class ClassDescriptor:
    def __init__(self, vtable, namestr):
        self.vtable = vtable
        self.namestr = namestr
        self.bases = []

    def add_base(self, base, offset=0, flags=0):
        self.bases.append(BaseClass(base, offset, flags))

def tinfo2class(tiname):
  s = Demangle(tiname, 0)
  if s is None:
      return s
  return s.replace("`typeinfo for'","")

def classname(namestr):
  return tinfo2class("__ZTI" + namestr)

# dd `vtable for'std::type_info+8
# dd `typeinfo name for'std::type_info
def format_type_info(ea):
  # get the class name string
  tis = u.get_ptr(ea + u.PTR_SIZE)
  if u.is_bad_addr(tis):
    return BADADDR
  name = GetString(tis)
  if name == None or len(name) == 0:
    return BADADDR
  # looks good, let's do it
  ea2 = u.format_struct(ea, "vp")
  u.force_name(tis, "__ZTS" + name)
  u.force_name(ea, "__ZTI" + name)
  # find our vtable
  # 0 followed by ea
  pat = u.ptr_to_bytes(0) + " " + u.ptr_to_bytes(ea)
  vtb = FindBinary(0, SEARCH_CASE|SEARCH_DOWN, pat)
  if not u.is_bad_addr(vtb):
    print("vtable for %s at %08X" % (name, vtb))
    u.format_struct(vtb, "pp")
    u.force_name(vtb, u.vtname(name))
  else:
    vtb = BADADDR
  all_classes[ea] = ClassDescriptor(vtb, name)
  return ea2

# dd `vtable for'__cxxabiv1::__si_class_type_info+8
# dd `typeinfo name for'MyClass
# dd `typeinfo for'BaseClass
def format_si_type_info(ea):
  ea2 = format_type_info(ea)
  pbase = u.get_ptr(ea2)
  all_classes[ea].add_base(pbase)
  ea2 = u.format_struct(ea2, "p")
  return ea2

# dd `vtable for'__cxxabiv1::__si_class_type_info+8
# dd `typeinfo name for'MyClass
# dd flags
# dd base_count
# (base_type, offset_flags) x base_count
def format_vmi_type_info(ea):
  ea2 = format_type_info(ea)
  ea2 = u.format_struct(ea2, "ii")
  base_count = Dword(ea2-4)
  clas = all_classes[ea]
  if base_count > 100:
    print("%08X: over 100 base classes?!" % ea)
    return BADADDR
  for i in range(base_count):
    base_ti = u.get_ptr(ea2)
    flags_off = u.get_ptr(ea2 + u.PTR_SIZE)
    off = u.SIGNEXT(flags_off>>8, 24)
    clas.add_base(base_ti, off, flags_off & 0xFF)
    ea2 = u.format_struct(ea2, "pl")
  return ea2

def find_type_info(idx):
  name = ti_names[idx]
  ea = u.find_string(name)
  if ea != BADADDR:
    xrefs = u.xref_or_find(ea)
    if xrefs:
      ti_start = xrefs[0] - u.PTR_SIZE
      if not u.is_bad_addr(ti_start):
        print("found %d at %08X" % (idx, ti_start))
        ea2 = format_type_info(ti_start)
        if idx >= TI_CTINFO:
          u.format_struct(ea2, "p")

def handle_classes(idx, formatter):
  name = u.vtname(ti_names[idx])
  ea = LocByName(name)
  if ea == BADADDR:
    # try single underscore
    name = name[1:]
    ea = LocByName(name)
  if ea == BADADDR:
    print("Could not find vtable for %s" % ti_names[idx])
    return
  idx = 0
  handled = set()
  while ea != BADADDR:
    print("Looking for refs to vtable %08X" % ea)
    if idaapi.is_spec_ea(ea):
      xrefs = u.xref_or_find(ea, True)
      ea += u.PTR_SIZE*2
      xrefs.extend(u.xref_or_find(ea, True))
    else:
      ea += u.PTR_SIZE*2
      xrefs = u.xref_or_find(ea, True)
    for x in xrefs:
      if not u.is_bad_addr(x) and not x in handled:
        print("found %s at %08X" % (name, x))
        ea2 = formatter(x)
        handled.add(x)
    ea = LocByName("%s_%d" % (name, idx))
    idx += 1

def run_gcc():
    classes = {}
    # turn on GCC3 demangling
    idaapi.cvar.inf.demnames |= idaapi.DEMNAM_GCC3
    print("Looking for standard type info classes")
    find_type_info(TI_TINFO)
    find_type_info(TI_CTINFO)
    find_type_info(TI_SICTINFO)
    find_type_info(TI_VMICTINFO)
    print("Looking for simple classes")
    handle_classes(TI_CTINFO, format_type_info)
    print("Looking for single-inheritance classes")
    handle_classes(TI_SICTINFO, format_si_type_info)
    print("Looking for multiple-inheritance classes")
    handle_classes(TI_VMICTINFO, format_vmi_type_info)
    for i in range(len(all_classes)):
        tiaddr = u.num2key(all_classes)[i]
        klass = all_classes[tiaddr]
        name = classname(klass.namestr)
        ti = "%08X" % tiaddr
        vt = "%08X" % klass.vtable
        basestr = []
        for b in klass.bases:
            if b.ti in all_classes:
                bklass = all_classes[b.ti]
                basename = classname(bklass.namestr)
            elif idaapi.is_spec_ea(b.ti):
                nm = Name(b.ti)
                basename = tinfo2class(nm)
            else:
                print("Base %08X not found for class %08X!" % (b.ti, tiaddr))
                basename = "ti_%08X" % b.ti
            basestr.append(basename)
        classes[name] = basestr
        print("basestr: \"%s\"" % basestr)
    return classes
