from idaapi import *

FINISHED_MESSAGE = """\
MotionScript processor for IDA

Copyright (C) 2017 Sammi Husky [sammi-husky@live.com]

licensed under the MIT license - see LICENSE file in project
root for more information.
"""

class MSCSBProcessor(processor_t):
    id = 0x8000 + 5348
    flag = PR_ADJSEGS | PRN_HEX
    cnbits = 8
    dnbits = 8
    psnames = ["mscsb"]
    plnames = ["SM4SH MotionScript"]
    segreg_size = 0
    instruc_start = 0

    assembler = {
        "flag" : ASH_HEXF3 | ASD_DECF0 | ASO_OCTF1 | ASB_BINF3 | AS_NOTAB
               | AS_ASCIIC | AS_ASCIIZ,
        "uflag": 0,
        "name": "GNU assembler",

        "origin": ".org",
        "end": "end",
        "cmnt": ";",

        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",

        "a_ascii": ".ascii",
        "a_byte": ".word",
        "a_word": ".dword",

        "a_bss": "dfs %s",

        "a_seg": "seg",
        "a_curip": ".",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extrn",
        "a_comdef": "",
        "a_align": ".align",

        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    regNames = ["$%s" % n for n in [
        "GV0","GV1","GV2","GV3","GV4","GV5",
        "GV6","GV7","GV8","GV9","GV10","GV11",
        "GV12","GV13","GV14","GV15","GV16","GV17",
        "GV18","GV19","GV20","GV21","GV22","GV23",
        "GV24","GV25","GV26","GV27","GV28","GV29",
        "GV30","GV31","GV32","GV33","GV34","GV35",
        "GV36","GV37","GV38","GV39","GV40","GV41",
        "GV42","GV43","GV44","GV45","GV46","GV47",
        "GV48","GV49","GV50","GV51","GV52","GV53",
        "GV54","GV55","GV56","GV57","GV58","GV59",
        "GV60","GV61", "CS", "DS"
    ]]

    def __init__(self):
        processor_t.__init__(self)
        self._init_instructions()
        self._init_registers()    

    def _init_instructions(self):
        class insr:
            def __init__(self, name, cf, d, cmt):
                self.name = name
                self.cf = cf
                self.d = d
                self.cmt = cmt

        
        self.itable = {
            0x00: insr(name="nop",                     cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x02: insr(name="BeginSub",                cf=CF_USE2,              d=self.decode_begin,            cmt= None),
            0x03: insr(name="End",                     cf=CF_STOP,              d=self.decode_no_ops,           cmt= None),
            0x04: insr(name="jump4",                   cf=CF_USE1 | CF_JUMP,    d=self.decode_jump,             cmt= None),
            0x05: insr(name="jump5",                   cf=CF_USE1 | CF_JUMP,    d=self.decode_jump,             cmt= None),
            0x06: insr(name="return_6",                cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x07: insr(name="return_7",                cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x08: insr(name="return_8",                cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x09: insr(name="return_9",                cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x0a: insr(name="pushInt",                 cf=CF_USE1,              d=self.decode_push,             cmt= None),
            0x0b: insr(name="pushReg",                 cf=CF_USE1,              d=self.decode_push,             cmt= None),
            0x0d: insr(name="pushShort",               cf=CF_USE1,              d=self.decode_push,             cmt= None),
            0x0e: insr(name="addi",                    cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x0f: insr(name="subi",                    cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x10: insr(name="multi",                   cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x11: insr(name="divi",                    cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x12: insr(name="modi",                    cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x13: insr(name="negi",                    cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x14: insr(name="i++",                     cf=None,                 d=self.decode_reg,              cmt= lambda: "i++"),
            0x15: insr(name="i--",                     cf=None,                 d=self.decode_reg,              cmt= lambda: "i--"),
            0x16: insr(name="BitwiseAnd",              cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x17: insr(name="BitwiseOr",               cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x18: insr(name="BitwiseNot",              cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x19: insr(name="BitwiseXor",              cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x1a: insr(name="leftShift",               cf=CF_SHFT,              d=self.decode_no_ops,           cmt= None),
            0x1b: insr(name="rightShift",              cf=CF_SHFT,              d=self.decode_no_ops,           cmt= None),
            0x1c: insr(name="setVar",                  cf=CF_USE1,              d=self.decode_set,              cmt= None),
            0x1d: insr(name="i+=",                     cf=CF_USE1,              d=self.decode_reg,              cmt= lambda: "+="),
            0x1e: insr(name="i-=",                     cf=CF_USE1,              d=self.decode_reg,              cmt= lambda: "-="),
            0x1f: insr(name="i*=",                     cf=CF_USE1,              d=self.decode_reg,              cmt= lambda: "*="),
            0x20: insr(name="i/=",                     cf=CF_USE1,              d=self.decode_reg,              cmt= lambda: "/="),
            0x21: insr(name="i%=",                     cf=CF_USE1,              d=self.decode_reg,              cmt= lambda: "%="),
            0x22: insr(name="i&=",                     cf=CF_USE1,              d=self.decode_reg,              cmt= lambda: "&="),
            0x23: insr(name="i|=",                     cf=CF_USE1,              d=self.decode_reg,              cmt= lambda: "|="),
            0x24: insr(name="i^=",                     cf=CF_USE1,              d=self.decode_reg,              cmt= lambda: "^="),
            0x25: insr(name="equals",                  cf=None,                 d=self.decode_no_ops,           cmt= lambda: "=="),
            0x26: insr(name="notEqual",                cf=None,                 d=self.decode_no_ops,           cmt= lambda: "!="),
            0x27: insr(name="lessThan",                cf=None,                 d=self.decode_no_ops,           cmt= lambda: "<"),
            0x28: insr(name="lessOrEqual",             cf=None,                 d=self.decode_no_ops,           cmt= lambda: "<="),
            0x29: insr(name="greater",                 cf=None,                 d=self.decode_no_ops,           cmt= lambda: ">"),
            0x2a: insr(name="greaterOrEqual",          cf=None,                 d=self.decode_no_ops,           cmt= lambda: ">="),
            0x2b: insr(name="isZero",                  cf=None,                 d=self.decode_no_ops,           cmt= lambda: "== 0"),
            0x2c: insr(name="printf",                  cf=CF_USE1,              d=self.decode_printf,           cmt= self.cmt_printf),
            0x2d: insr(name="sys",                     cf=CF_USE2,              d=self.decode_sys,              cmt= None),
            0x2e: insr(name="unk_2E",                  cf=CF_USE1,              d=self.decode_jump,             cmt= None),
            0x2f: insr(name="Call_Func2",              cf=CF_CALL | CF_USE1,    d=self.decode_call,             cmt= None),
            0x30: insr(name="call_func3",              cf=CF_CALL | CF_USE1,    d=self.decode_call,             cmt= None),
            0x31: insr(name="Call_Func4",              cf=CF_CALL | CF_USE1,    d=self.decode_call,             cmt= None),
            0x32: insr(name="push",                    cf=None,                 d=None,                         cmt= None),
            0x33: insr(name="pop",                     cf=None,                 d=None,                         cmt= None),
            0x34: insr(name="if",                      cf=CF_USE1,              d=self.decode_jump,             cmt= None),
            0x35: insr(name="ifNot",                   cf=CF_USE1,              d=self.decode_jump,             cmt= None),
            0x36: insr(name="else",                    cf=CF_USE1,              d=self.decode_jump,             cmt= None),
            0x37: insr(name="unk_37",                  cf=None,                 d=None,                         cmt= None),
            0x38: insr(name="intToFloat",              cf=CF_USE1,              d=self.decode_conversion,       cmt= None),
            0x39: insr(name="floatToInt",              cf=CF_USE1,              d=self.decode_conversion,       cmt= None),
            0x3a: insr(name="addf",                    cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x3b: insr(name="subf",                    cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x3c: insr(name="multf",                   cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x3d: insr(name="divf",                    cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x3e: insr(name="negf",                    cf=None,                 d=self.decode_no_ops,           cmt= None),
            0x3f: insr(name="f++",                     cf=None,                 d=self.decode_reg,              cmt= lambda: "f++"),
            0x40: insr(name="f--",                     cf=None,                 d=self.decode_reg,              cmt= lambda: "f--"),
            0x41: insr(name="floatVarSet",             cf=CF_USE1,              d=self.decode_set,              cmt= None),
            0x42: insr(name="float+=",                 cf=CF_USE1,              d=self.decode_reg,              cmt= lambda: "+="),
            0x43: insr(name="float-=",                 cf=CF_USE1,              d=self.decode_reg,              cmt= lambda: "-="),
            0x44: insr(name="float*=",                 cf=CF_USE1,              d=self.decode_reg,              cmt= lambda: "*="),
            0x45: insr(name="float/=",                 cf=CF_USE1,              d=self.decode_reg,              cmt= lambda: "/="),
            0x46: insr(name="floatGreater",            cf=None,                 d=self.decode_no_ops,           cmt= lambda: ">"),
            0x47: insr(name="floatLessOrEqual",        cf=None,                 d=self.decode_no_ops,           cmt= lambda: "<="),
            0x48: insr(name="floatLess",               cf=None,                 d=self.decode_no_ops,           cmt= lambda: "<"),
            0x49: insr(name="floatNotEqual",           cf=None,                 d=self.decode_no_ops,           cmt= lambda: "!="),
            0x4a: insr(name="floatEqual",              cf=None,                 d=self.decode_no_ops,           cmt= lambda: "=="),
            0x4b: insr(name="floatGreaterOrEqual",     cf=None,                 d=self.decode_no_ops,           cmt= lambda: ">="),
            0x4c: insr(name="unk_4c",                  cf=None,                 d=None,                         cmt= None),
            0x4d: insr(name="exit",                    cf=None,                 d=None,                         cmt= None)
        }
        
        # Now create an instruction table compatible with IDA processor module requirements
        for i in xrange(0, 6):
            self.cmd[i].type = o_void
            
        Instructions = []
        i = 0
        for x in self.itable.values():
            d = dict(name=x.name, feature=x.cf)
            if x.cmt != None:
                d['cmt'] = x.cmt
            Instructions.append(d)
            setattr(self, 'itype_' + x.name, i)
            i += 1

        # icode of the last instruction + 1
        self.instruc_end = len(Instructions) + 1

        # Array of instructions
        self.instruc = Instructions

    def _init_registers(self):
        self.reg_ids = {}
        for i, reg in enumerate(self.regNames):
            self.reg_ids[reg] = i

        # IDA needs these so lets fake it...
        self.regFirstSreg = self.regCodeSreg = self.reg_ids["$CS"]
        self.regLastSreg = self.regDataSreg = self.reg_ids["$DS"]
 
    #----------------------------------------------------------------#
    #---------------- Opcode Decoders -------------------------------#
    #----------------------------------------------------------------#
    def _read_cmd_byte(self):
        ea = self.cmd.ea + self.cmd.size
        byte = get_byte(ea)
        self.cmd.size += 1
        return byte
        
    def _read_cmd_word(self):
        ea = self.cmd.ea + self.cmd.size
        word = get_word(ea)
        self.cmd.size += 2
        return word
        
    def _read_cmd_dword(self):
        ea = self.cmd.ea + self.cmd.size
        dword = get_long(ea)
        self.cmd.size += 4
        return dword

    def _read_cmd_3byte(self):
        ea = self.cmd.ea + self.cmd.size
        val = get_3byte(ea)
        self.cmd.size += 3
        return val

    def decode_begin(self, opcode):
        self.cmd[0].type = o_imm
        self.cmd[0].dtyp = dt_word
        self.cmd[0].value = self._read_cmd_word()
        self.cmd[1].type = o_imm
        self.cmd[1].dtyp = dt_word
        self.cmd[1].value = self._read_cmd_word()
        return True
        
    def decode_jump(self, opcode):
        self.cmd[0].type = o_near
        self.cmd[0].dtyp = dt_word
        self.cmd[0].addr = self._read_cmd_dword() - 0x10 
        return True
        
    def decode_push(self, opcode):
        if opcode == 0x0A:
            self.cmd[0].type = o_imm
            self.cmd[0].dtyp = dt_word
            self.cmd[0].value = self._read_cmd_dword()
        if opcode == 0x0B:
            self.decode_reg(opcode)
        if opcode == 0x0D:
            self.cmd[0].type = o_imm
            self.cmd[0].dtyp = dt_word
            self.cmd[0].value = self._read_cmd_word()
        return True
        
    def decode_set(self, opcode):
        self.decode_reg(opcode)
        return True
        
    def decode_reg(self, opcode):
        regType = self._read_cmd_byte()
        if regType == 1:
            self.cmd[0].type = o_reg
            self.cmd[0].dtyp = dt_3byte
            self.cmd[0].reg = self._read_cmd_word()
        else:
            self.cmd[0].type = o_imm
            self.cmd[0].dtyp = dt_3byte
            self.cmd[0].value = self._read_cmd_word()
        return True
    
    def cmt_printf(self):
        seg = get_segm_by_name("DATA")
        
        '''
            Loader abuses segment orgbase and sets it to string chunk size
        '''
        chunkSize= seg.orgbase
        index = cmd[5].value
        return GetString(seg.startEA + (index * chunkSize))
            
    def decode_printf(self, opcode):
        c = 0
        addr = self.cmd.ea
        while c != 0x8D:
            addr -= 1
            c = get_byte(addr)
            
        val = get_word(addr + 1)
        self.cmd[0].type = o_imm
        self.cmd[0].dtyp = dt_byte
        self.cmd[0].value = self._read_cmd_byte()
        
        self.cmd[5].value = val # abuse op 6 for printf... HACKY!
        return True
        
    def decode_call(self, opcode):
        self.cmd[0].type = o_near
        self.cmd[0].dtyp = dt_byte 
        if get_byte(self.cmd.ea - 5) == 0x8A:
            self.cmd[0].addr = get_long(self.cmd.ea - 4) - 0x10
        self._read_cmd_byte()
        return True
        
    def decode_sys(self, opcode):
        self.cmd[0].type = o_imm
        self.cmd[0].dtyp = dt_byte
        self.cmd[0].value = self._read_cmd_byte()
        self.cmd[1].type = o_imm
        self.cmd[1].dtyp = dt_byte
        self.cmd[1].value = self._read_cmd_byte()
        return True
    
    def decode_conversion(self, opcode):
        self.cmd[0].type = o_imm
        self.cmd[0].dtyp = dt_byte
        self.cmd[0].value = self._read_cmd_byte()
        return True
  
    def decode_no_ops(self, opcode):
        return True

    #----------------------------------------------------------------#
    #---------------- IDA callback funcs ----------------------------#
    #----------------------------------------------------------------#

    def notify_init(self, idp_file):
        cvar.inf.mf = True # Tell IDA it's big endian data
        return True
        
    def notify_get_autocmt(self):
        """
        Get instruction comment. 'cmd' describes the instruction in question
        @return: None or the comment string
        """
        if 'cmt' in self.instruc[self.cmd.itype]:
            return self.instruc[self.cmd.itype]['cmt']()

    def notify_endbinary(self, ok):
        if ok:
            print FINISHED_MESSAGE
            
    def ana(self):
        cmd = self.cmd
        
        # take opcode byte
        b = self._read_cmd_byte()
        
        # clear push bit
        opcode = b & 0x7F
        cmd.auxpref = b >> 7 # pushes to MSC stack?

        try:
            ins = self.itable[opcode]
            # set default itype
            self.cmd.itype = getattr(self, 'itype_' + ins.name)
        except:
            return 0
        
        # call the decoder
        if ins.d is None:
            return 0
        
        ins.d(opcode)
        
        return self.cmd.size

    def emu(self): 
        for i in xrange(6):
            if cmd[i].type == o_void:
                break

            if self.cmd[i].type == o_near:
                if self.cmd.get_canon_feature() & CF_CALL:
                    fl = fl_CN
                else:
                    fl = fl_JN
                ua_add_cref(0, self.cmd[i].addr, fl)
    
        if not self.cmd.get_canon_feature() & CF_STOP:  # add a link to next instr if code continues
            ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)
    
        return True

    def outop(self, op):
        if op.type == o_reg:
            out_register(self.regNames[op.reg])
        elif op.type == o_imm:
            OutValue(op, OOFW_IMM)
        elif op.type == o_near:
            ok = out_name_expr(op, op.addr, BADADDR)
            if not ok:
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueMark(Q_noName, self.cmd.ea)
        else:
            return False
        return True

    def out(self):
        cmd = self.cmd

        buf = init_output_buffer(1024)
        if cmd.auxpref == 1:
            OutLine('-> ')
        else:
            OutLine('   ') # make sure things are pretty still
            
        OutMnem(15)  # max width = 15

        for i in xrange(0, 6):
            if cmd[i].type == o_void:
                break

            if i != 0:
                out_symbol(',')
                OutChar(' ')

            out_one_operand(i)


        term_output_buffer()
        cvar.gl_comm = 1  # allow comments at end of line
        MakeLine(buf)

def PROCESSOR_ENTRY():
    return MSCSBProcessor()