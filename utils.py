import struct
import idaapi
from idc import *
from idaapi import get_segm_by_name, has_xref, get_full_flags, opinfo_t, refinfo_t,\
get_32bit, get_64bit, get_imagebase, get_byte
import idautils
from idautils import DataRefsTo

# Segments
within = lambda x, rl: any([True for r in rl if r[0]<=x<=r[1]])

class utils(object):
    text = 0
    data = 0
    rdata = 0
    valid_ranges = []
    within = lambda self, x, rl: any([True for r in rl if r[0]<=x<=r[1]])

    REF_OFF = 0
    x64 = 0
    PTR_TYPE = 0
    PTR_SIZE = 0

    def __init__(self):
        self.text = get_segm_by_name(".text")
        self.data = get_segm_by_name(".data")
        self.rdata = get_segm_by_name(".rdata")
        # try to use rdata if there actually is an rdata segment, otherwise just use data
        if self.rdata is not None:
            self.valid_ranges = [(self.rdata.start_ea, self.rdata.end_ea), (self.data.start_ea, self.data.end_ea)]
        else:
            self.valid_ranges = [(self.data.start_ea, self.data.end_ea)]

        self.x64 = (idaapi.getseg(here()).bitness == 2)
        if self.x64:
            self.PTR_TYPE = FF_QWORD
            self.REF_OFF = REF_OFF64
            self.PTR_SIZE = 8
            self.get_ptr = get_64bit
        else:
            self.PTR_TYPE = FF_DWORD
            self.REF_OFF = REF_OFF32
            self.PTR_SIZE = 4
            self.get_ptr = get_32bit

# for 32-bit binaries, the RTTI structs contain absolute addresses, but for
# 64-bit binaries, they're offsets from the image base.
    def x64_imagebase(self):
        if self.x64:
            return get_imagebase()
        else:
            return 0

    def mt_rva(self):
        ri = refinfo_t()
        ri.flags = self.REF_OFF
        ri.target = 0
        mt = opinfo_t()
        mt.ri = ri
        return mt

    def mt_address(self):
        ri = refinfo_t()
        ri.flags = self.REF_OFF
        ri.target = 0
        mt = opinfo_t()
        mt.ri = ri
        return mt

    def mt_ascii(self):
        ri = refinfo_t()
        ri.flags = STRTYPE_C
        ri.target = -1
        mt = opinfo_t()
        mt.ri = ri
        return mt

    def get_strlen(self, addr):
        strlen = 0
        while get_byte(addr+strlen) != 0x0 and strlen < 50:
            strlen+=1
        #assume no names will ever be longer than 50 bytes
        if strlen == 50:
            return None
        return strlen

    def isVtable(self, addr):
        function = self.get_ptr(addr)
        # Check if vtable has ref and its first pointer lies within code segment
        if has_xref(get_full_flags(addr)) and function >= self.text.start_ea and function <= self.text.end_ea:
            return True
        return False

# helper for bin search
    def ptr_to_bytes(self, val):
      if self.x64:
        sv = struct.pack("<Q", val)
      else:
        sv = struct.pack("<I", val)
      return " ".join("%02X" % b for b in sv)

    def ptrfirst(self, val):
      return find_binary(0, SEARCH_CASE|SEARCH_DOWN, self.ptr_to_bytes(val))

    def ptrnext(self, val, ref):
      return find_binary(ref+1, SEARCH_CASE|SEARCH_DOWN, self.ptr_to_bytes(val))

    def xref_or_find(self, addr, allow_many = False):
      lrefs = list(DataRefsTo(addr))
      if len(lrefs) == 0:
        lrefs = list(idautils.refs(addr, self.ptrfirst, self.ptrnext))
      if len(lrefs) > 1 and not allow_many:
          print("too many xrefs to %08X" % addr)
          return []
      lrefs = [r for r in lrefs if not is_code(get_full_flags(r))]
      return lrefs

    def find_string(self, s, afrom=0):
      print("searching for %s" % s)
      ea = find_binary(afrom, SEARCH_CASE|SEARCH_DOWN, '"' + s + '"')
      if ea != BADADDR:
        print("Found at %08X" % ea)
      return ea

    def ForceDword(self, ea):
      if ea != BADADDR and ea != 0:
        if not is_dword(get_full_flags(ea)):
          del_items(ea, 4, DELIT_SIMPLE)
          create_data(ea, FF_DWORD, 4, BADADDR)
        if is_off0(get_full_flags(ea)) and get_fixup_target_type(ea) == -1:
          # remove the offset
          op_hex(ea, 0)

    def ForceQword(self, ea):
      if ea != BADADDR and ea != 0:
        if not is_qword(get_full_flags(ea)):
          del_items(ea, 8, DELIT_SIMPLE)
          create_data(ea, FF_QWORD, 8, BADADDR)
        if is_off0(get_full_flags(ea)) and get_fixup_target_type(ea) == -1:
          # remove the offset
          op_hex(ea, 0)

    def ForcePtr(self, ea, delta = 0):
      if self.x64:
        self.ForceQword(ea)
      else:
        self.ForceDword(ea)
      if get_fixup_target_type(ea) != -1 and is_off0(get_full_flags(ea)):
        # don't touch fixups
        return
      pv = self.get_ptr(ea)
      if pv != 0 and pv != BADADDR:
        # apply offset again
        if idaapi.is_spec_ea(pv):
          delta = 0
        op_offset(ea, 0, [REF_OFF32, REF_OFF64][self.x64], -1, 0, delta)

# p pointer
# v vtable pointer (delta ptrsize*2)
# i integer (32-bit)
# l integer (32 or 64-bit)
    def format_struct(self, ea, fmt):
      for f in fmt:
        if f in ['p', 'v']:
          if f == 'v':
            delta = self.PTR_SIZE*2
          else:
            delta = 0
          self.ForcePtr(ea, delta)
          ea += self.PTR_SIZE
        elif f == 'i':
          self.ForceDword(ea)
          ea += 4
        elif f == 'l':
          if self.x64:
            self.ForceQword(ea)
            ea += 8
          else:
            self.ForceDword(ea)
            ea += 4
      return ea

    def force_name(self, ea, name):
      if is_tail(get_full_flags(ea)):
        del_items(ea, 1, DELIT_SIMPLE)
      set_name(ea, name, SN_NOWARN)

    def is_bad_addr(self, ea):
      return ea == 0 or ea == BADADDR or idaapi.is_spec_ea(ea) or not is_loaded(ea)

    def vtname(self, name):
      return "__ZTV" + name

# sign extend b low bits in x
# from "Bit Twiddling Hacks"
    def SIGNEXT(self, x, b):
        m = 1 << (b - 1)
        x = x & ((1 << b) - 1)
        return (x ^ m) - m

    def xref_or_find(self, addr, allow_many = False):
        lrefs = list(DataRefsTo(addr))
        if len(lrefs) == 0:
            lrefs = list(idautils.refs(addr, self.ptrfirst, self.ptrnext))
        if len(lrefs) > 1 and not allow_many:
            print("too many xrefs to %08X" % addr)
            return []
        lrefs = [r for r in lrefs if not is_code(get_full_flags(r))]
        return lrefs

    def num2key(self, all_classes):
        return [k for k in all_classes]

    def add_missing_classes(self, classes):
        missing = []
        for c, parents in classes.items():
            for parent in parents:
                if parent not in classes.keys():
                    missing.append(parent)
        for m in missing:
            classes[m] = []
