"""
MotionScript Binary (mscsb) loader for IDA

Copyright (C) 2017 Sammi Husky [sammi-husky@live.com]
Copyright (C) 2017 jam1garner

licensed under the MIT license - see LICENSE file in project
root for more information.
"""

import os,sys,struct
from idaapi import *

class MSCFile:
    def __init__(self, f, endian='<'):
        self.offsets = []
        self.entryPoint = 0

        self.textSize = 0
        self.textStart = 0
        self.dataStart = 0
        self.dataEnd = 0
        self.entriesPos = 0
        self.stringCount = 0
        self.stringSize = 0
        self.read(f, endian)

    def read(self, f, endian):
        f.seek(0x10)
        #Get the end of script offset and add 0x30 to make it absolute
        pEntryOffs = struct.unpack(endian+'I', f.read(4))[0] + 0x30

        #Add the padding size to get the offset of the script indices
        self.entriesPos = pEntryOffs
        if pEntryOffs % 0x10 != 0:
            pEntryOffs += 0x10 - (pEntryOffs % 0x10)

        #Read in the offset of the initialization script so it can be labelled
        self.entryPoint = struct.unpack(endian+'I', f.read(4))[0]
        entryCount = struct.unpack(endian+'I', f.read(4))[0]

        f.seek(4, 1)
        self.stringSize = struct.unpack(endian+'I', f.read(4))[0]
        self.stringCount = struct.unpack(endian+'I', f.read(4))[0]

        #Read in the offsets for the scripts
        f.seek(pEntryOffs)
        for i in range(entryCount):
            self.offsets.append(struct.unpack(endian+'I', f.read(4))[0] + 0x30)

        #File is padded to 0x10 after the script offsets, skip the padding
        if f.tell() % 0x10 != 0:
            f.seek(0x10 - (f.tell() % 0x10), 1)

        #Calculate size of string section (which is marked as data)
        self.dataStart = f.tell()
        self.dataEnd = f.tell() + (self.stringSize * self.stringCount)

        #Sort to find the offset located closest to the beginning on the file
        sorted = self.offsets
        sorted.sort()

        #Calculate bounds of script data
        self.textSize = self.entriesPos - sorted[0]
        self.textStart = sorted[0]

SECTION_CLASSES = {
    b".text\0\0\0": "CODE",
    b".data\0\0\0": "DATA",
    b".reloc\0\0":  "DATA",
    b"_TEXT_RE":    "CODE",
    b"_TEXT_PR":    "CODE"
}

SECTION_MODES = {
    b"_TEXT_RE":    0,
}

def load_file(f, neflags, format):
    set_processor_type('mscsb',1)

    #Read in file ('<' being LE for the header)
    msc = MSCFile(f, '<')

    SEG1_START = 0
    SEG2_START = msc.textSize

    # add text segment
    f.file2base(msc.textStart, SEG1_START, msc.textSize, 0)
    add_segm(0, 0, msc.textSize, 'TEXT', "CODE")

    # add string data segment
    f.file2base(msc.dataStart, SEG2_START, msc.textSize + (msc.dataEnd - msc.dataStart), 0)
    add_segm(0, SEG2_START, msc.textSize + msc.dataEnd - msc.dataStart, 'DATA', "DATA")

    # abuse orgbase to tell the processor module the string chunk size
    get_segm_by_name("DATA").orgbase = msc.stringSize

    # Do each script as an entrypoint to ensure each location is added
    # as it's own function in the function list. (With name) May be a better way?
    for i, off in enumerate(msc.offsets):
        if off - 0x30 == msc.entryPoint:
            add_entry(off - msc.textStart, off - msc.textStart, '_entrypoint', 1)
        else:
            add_entry(off - msc.textStart, off - msc.textStart,'script_%d' % i, 1)

    # Mark the strings in DATA segment as strings
    for i in xrange(msc.stringCount):
        off = msc.textSize + (i * msc.stringSize)
        MakeStr(off,0xffffffff)

    return 1

def accept_file(f, n):
    retval = 0

    if n == 0:
        f.seek(0)
        if struct.unpack('>I', f.read(4))[0] == 0xB2ACBCBA:
            retval = "SM4SH MotionScript Binary"

    return retval
