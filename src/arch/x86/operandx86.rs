// operandx86.rs
use arch::x86::archx86::*;
use arch::x86::prefixx86::*;
use arch::x86::instructionsx86::*;
use arch::x86::disasmtablesx86::*;
use arch::x86::opcodex86::*;


#[repr(u16)]
/// Needed to process the opcode
pub enum Attributes {
    AttrNone=0x00,
    Attr64BIT=0x1 << 0,
    AttrXS=0x1 << 1,
    AttrXD=0x1 << 2,
    AttrREXW=0x1 << 3,
    AttrOPSIZE=0x1 << 4,
    AttrADSIZE=0x1 << 5,
    AttrVEX=0x1 << 6,
    AttrVEXL=0x1 << 7,
    AttrEVEX=0x1 << 8,
    AttrEVEXL=0x1 << 9,
    AttrEVEXL2=0x1 << 10,
    AttrEVEXK=0x1 << 11,
    AttrEVEXKZ=0x1 << 12,
    AttrEVEXB=0x1 << 13,
}

fn check_modrm(
    _instr: &mut Instructionx86, 
    instr_class: &DisassemblerContextsx86) -> bool
{
    disasm_debug!("check_modrm()");
    let mut opcode: u16 = _instr.opcode.data[0] as u16;
    if _instr.opcode.size == 2 {
        opcode = _instr.opcode.data[1] as u16;
    }
    disasm_debug!("check modrm opcode: {:?}", opcode);

    match _instr.opcode.kind{
        OpcodeTypex86::OneByte=>{
            let index: u32 = DISASMX86_ONEBYTE_INDEX[*instr_class as usize];
            if index == 0 { return false; }
            match DISASMX86_ONEBYTE_OPCODES[index as usize-1][opcode as usize].modtype{
                md if md == ModRMTypes::ModRMOneEntry as u32=> return false,
                _=> return true,
            }
        },
        OpcodeTypex86::TwoByte=>{
            let index: u32 = DISASMX86_TWOBYTE_INDEX[*instr_class as usize];
            if index == 0 { return false; }
            match DISASMX86_TWOBYTE_OPCODES[index as usize-1][opcode as usize].modtype{
                md if md == ModRMTypes::ModRMOneEntry as u32=> return false,
                _=> return true,
            }
        },
        OpcodeTypex86::ThreeByte38=>{
            let index: u32 = DISASMX86_THREEBYTE_38INDEX[*instr_class as usize];
            if index == 0 { 
                return false; 
            }
            match DISASMX86_THREEBYTE_38OPCODES[index as usize-1][opcode as usize].modtype{
                md if md == ModRMTypes::ModRMOneEntry as u32=>return false,
                _=> return true,
            }
        },
        OpcodeTypex86::ThreeByte3A=>{
            let index: u32 = DISASMX86_THREEBYTE_3AINDEX[*instr_class as usize];
            if index == 0 { return false; }
            match DISASMX86_THREEBYTE_3AOPCODES[index as usize-1][opcode as usize].modtype{
                md if md == ModRMTypes::ModRMOneEntry as u32=> return false,
                _=> return true,
            }
        },
        OpcodeTypex86::Xop8Map=>{
            let index: u32 = DISASMX86_XOP8_INDEX[*instr_class as usize];
            if index == 0 { return false; }
            match DISASMX86_XOP8_OPCODES[index as usize-1][opcode as usize].modtype{
                md if md == ModRMTypes::ModRMOneEntry as u32=> return false,
                _=> return true,
            }
        },
        OpcodeTypex86::Xop9Map=>{
            let index: u32 = DISASMX86_XOP9_INDEX[*instr_class as usize];
            if index == 0 { return false; }
            match DISASMX86_XOP9_OPCODES[index as usize-1][opcode as usize].modtype{
                md if md == ModRMTypes::ModRMOneEntry as u32=> return false,
                _=> return true,
            }
        },
        OpcodeTypex86::XopAMap=>{
            let index: u32 = DISASMX86_XOPA_INDEX[*instr_class as usize];
            if index == 0 { return false; }
            match DISASMX86_XOPA_OPCODES[index as usize-1][opcode as usize].modtype{
                md if md == ModRMTypes::ModRMOneEntry as u32=> return false,
                _=> return true,
            }
        },
        OpcodeTypex86::T3dNowMap=>{
            // always has modrm
            return true;
        },
    }
}
/// get the instruction id from the disassembly tables
fn lookup_instr_disasm_tables(
    _opcode_type: &OpcodeTypex86,
    _instr_class: &DisassemblerContextsx86,
    _opcode: u16,
    _mod_rm: &u16,
    _instruction_index: &mut u16) -> bool
{
    disasm_debug!("lookup_instr_disasm_tables(\
        _opcode_type: {:?},\
        _instr_class: {:?}, \
        _opcode: {:?}, _mod_rm: {:?})",
        _opcode_type,
        _instr_class,
        _opcode,
        _mod_rm);
    *_instruction_index=0;
    let mut decision: Option<ModRMDecisionTypex86> = None;
    match *_opcode_type{
        OpcodeTypex86::OneByte=>{
            let index: usize = DISASMX86_ONEBYTE_INDEX[*_instr_class as usize] as usize;
            if index != 0 {
                decision = Some(DISASMX86_ONEBYTE_OPCODES[index-1][_opcode as usize]);
            }
        },
        OpcodeTypex86::TwoByte=>{
            let index: u32 = DISASMX86_TWOBYTE_INDEX[*_instr_class as usize];
            if index != 0 { 
                decision = Some(DISASMX86_TWOBYTE_OPCODES[index as usize-1][_opcode as usize]);
            }
        },
        OpcodeTypex86::ThreeByte38=>{
            let index: u32 = DISASMX86_THREEBYTE_38INDEX[*_instr_class as usize];
            if index != 0 { 
                decision = Some(DISASMX86_THREEBYTE_38OPCODES[index as usize-1][_opcode as usize]);
            }
        },
        OpcodeTypex86::ThreeByte3A=>{
            let index: u32 = DISASMX86_THREEBYTE_3AINDEX[*_instr_class as usize];
            if index != 0 { 
                decision = Some(DISASMX86_THREEBYTE_3AOPCODES[index as usize-1][_opcode as usize]);
            }
        },
        OpcodeTypex86::Xop8Map=>{
            let index: u32 = DISASMX86_XOP8_INDEX[*_instr_class as usize];
            if index != 0 { 
                decision = Some(DISASMX86_XOP8_OPCODES[index as usize-1][_opcode as usize]);
            }
        },
        OpcodeTypex86::Xop9Map=>{
            let index: u32 = DISASMX86_XOP9_INDEX[*_instr_class as usize];
            if index != 0 { 
                decision = Some(DISASMX86_XOP9_OPCODES[index as usize-1][_opcode as usize]);
            }
        },
        OpcodeTypex86::XopAMap=>{
            let index: u32 = DISASMX86_XOPA_INDEX[*_instr_class as usize];
            if index != 0 { 
                decision = Some(DISASMX86_XOPA_OPCODES[index as usize-1][_opcode as usize]);
            }
        },
        OpcodeTypex86::T3dNowMap=>{
            let index: u32 = DISASMX86_T3DNOW_INDEX[*_instr_class as usize];
            if index != 0 { 
                decision = Some(DISASMX86_T3DNOW_OPCODES[index as usize-1][_opcode as usize]);
            }
        },
    }
    disasm_debug!("\tdecision {:?}", decision);
    match decision{
        Some(ref dec)=>{
            match dec.modtype {
                d if d == ModRMTypes::ModRMOneEntry as u32=>{
                    disasm_debug!("\tModRMTypes::ModRMOneEntry");
                    *_instruction_index=DISASMX86_MODRM_TABLE[dec.max as usize] as u16;
                    
                },
                d if d == ModRMTypes::ModRMSplitRm as u32=>{
                    disasm_debug!("\tModRMTypes::ModRMSplitRm");
                    if accessor!(mod: *_mod_rm as u8) == 0x3 {
                        *_instruction_index=DISASMX86_MODRM_TABLE[dec.max as usize+1] as u16;
                    } else {
                        *_instruction_index=DISASMX86_MODRM_TABLE[dec.max as usize] as u16;
                    }
                },
                d if d == ModRMTypes::ModRMSplitReg as u32=>{
                    disasm_debug!("\tModRMTypes::ModRMSplitReg");
                    let offset: usize = (dec.max+((*_mod_rm as u8 & 0x38) >> 3) as u32) as usize;
                    if accessor!(mod: _mod_rm) == 0x3 {
                        *_instruction_index=DISASMX86_MODRM_TABLE[offset+8] as u16;
                    } else {
                        *_instruction_index=DISASMX86_MODRM_TABLE[offset] as u16;
                    }
                },
                d if d == ModRMTypes::ModRMSplitMisc as u32=>{
                    disasm_debug!("\tModRMTypes::ModRMSplitMisc");
                    if accessor!(mod: _mod_rm) == 0x3 {
                        let offset: usize = (dec.max+(*_mod_rm as u8 & 0x3f) as u32) as usize;
                        *_instruction_index=DISASMX86_MODRM_TABLE[offset+8] as u16;
                    } else {
                        let offset: usize = (dec.max+((*_mod_rm as u8 & 0x38) >> 3) as u32) as usize;
                         *_instruction_index=DISASMX86_MODRM_TABLE[offset] as u16;
                    }
                },
                d if d == ModRMTypes::ModRMFull as u32=>{
                    disasm_debug!("\tModRMTypes::ModRMFull");
                    let offset: usize = (dec.max+*_mod_rm as u32) as usize;

                    *_instruction_index=DISASMX86_MODRM_TABLE[offset] as u16;
                },
                _=>{
                    return false;
                },
            }
        },
        None=>{
            disasm_debug!("\tdecision is None");
        },
    }
    disasm_debug!("\t_instruction_index {:?}", *_instruction_index);
    return true;
}

fn get_instruction_index(_instr: &mut Instructionx86, 
    _attr: &u16, 
    _instruction_index: &mut u16) -> bool 
{
    disasm_debug!("get_instruction_index(\
        _attr: {:?},\
        _instruction_index: {:?})",
        _attr,
        _instruction_index);

    //default
    let instr_class: DisassemblerContextsx86; 
    // handle 3dNow!
    match _instr.opcode.kind{
        OpcodeTypex86::T3dNowMap=>{
            instr_class = DisassemblerContextsx86::ICOF;
        },
        _=>{
            instr_class = DISASMX86_INSTRUCTION_CONTEXT[*_attr as usize];
        },
    }
    let mut opcode: u16 = _instr.opcode.data[0] as u16;
    if _instr.opcode.size == 2 {
        opcode = _instr.opcode.data[1] as u16;
    }
    // handle ModRm
    if check_modrm(_instr, &instr_class)
    {
        if !opcode_read_modrm(_instr){ return false; }
        // get instruction id
        match _instr.mod_rm
        {
            Some(ref md)=>{
                if !lookup_instr_disasm_tables(
                    &_instr.opcode.kind,
                    &instr_class,
                    opcode,
                    &md.data,
                    _instruction_index)
                {
                    return false;
                }
            },
            None=>{ // Femms
                if !lookup_instr_disasm_tables(
                    &_instr.opcode.kind,
                    &instr_class,
                    opcode,
                    &0,
                    _instruction_index)
                {
                    return false;
                }
            },
        }
        
    } else {
        if !lookup_instr_disasm_tables(
            &_instr.opcode.kind,
            &instr_class,
            opcode,
            &0,
            _instruction_index)
        {
            return false;
        }
    }
    disasm_debug!("\tinstr_class: {:?}", instr_class);
    if *_instruction_index == 0 {
        return false;
    }
    return true;
}

fn verify_prefix(_instr: &mut Instructionx86, _prefix: u8) -> bool
{
    disasm_debug!("verify_prefix(_prefix: {:?})", _prefix);
    let location = _instr.prefix.offset;
    match _prefix {
        0x66=>{
            if _instr.prefix.location[PrefixMaskx86::OPSize as usize] == location
            {
                return true;
            }
        },
        0x67=>{
            if _instr.prefix.location[PrefixMaskx86::ADDRSize as usize] == location{
                return true;
            }
        },
        0xf3=>{
            let offset = location.wrapping_sub(_instr.start) as usize;
            if offset < _instr.cinfo.code.len(){
                if _instr.prefix.location[PrefixMaskx86::LORep as usize] == location &&
                _instr.cinfo.code[offset] == _prefix
                {
                    return true;
                }
            }
        },
        0xf2=>{
            let offset = location.wrapping_sub(_instr.start) as usize;
            if offset < _instr.cinfo.code.len(){
                if _instr.prefix.location[PrefixMaskx86::LORep as usize] == location &&
                _instr.cinfo.code[(location-_instr.start) as usize] == _prefix{
                    return true;
                }
            }
        },
        _=>{},

    }
    return false;
}

fn instr_vex_prefix(
    _instr: &mut Instructionx86, 
    attributes: &mut u16)
{
    disasm_debug!("instr_vex_prefix()");
    if _instr.prefix.vex_type != VexExType::NoXop{
        if _instr.prefix.vex_type == VexExType::EVex{
            *attributes |= Attributes::AttrEVEX as u16;
        } else {
            *attributes |= Attributes::AttrVEX as u16;
        }
        match _instr.prefix.vex_type{
            VexExType::EVex=>{
                match accessor!(EVexPP_3_4: _instr.prefix.vex_prefix[2]) {
                    vex if vex == VexPrefixx86::Vex66 as u8=>{
                        *attributes |= Attributes::AttrOPSIZE as u16;
                    },
                    vex if vex == VexPrefixx86::VexF3 as u8=>{
                        *attributes |= Attributes::AttrXS as u16;
                    },
                    vex if vex == VexPrefixx86::VexF2 as u8=>{
                        *attributes |= Attributes::AttrXD as u16;
                    },
                    _=>{},
                }
                if accessor!(EVexZ_4_4: _instr.prefix.vex_prefix[3]) != 0 {
                    *attributes |= Attributes::AttrEVEXKZ as u16;
                }
                if accessor!(EVexB_4_4: _instr.prefix.vex_prefix[3]) != 0 {
                    *attributes |= Attributes::AttrEVEXB as u16;
                }
                if accessor!(EVexAAA_4_4: _instr.prefix.vex_prefix[3]) != 0 {
                    *attributes |= Attributes::AttrEVEXK as u16;
                }
                if accessor!(EVexL_4_4: _instr.prefix.vex_prefix[3]) != 0 {
                    *attributes |= Attributes::AttrEVEXL as u16;
                }
                if accessor!(EVexL2_4_4: _instr.prefix.vex_prefix[3]) != 0 {
                    *attributes |= Attributes::AttrEVEXL2 as u16;
                }
            },
            VexExType::Vex3B=>{
                match accessor!(VexPP_3_3: _instr.prefix.vex_prefix[2]) {
                    vex if vex == VexPrefixx86::Vex66 as u8=>{
                        *attributes |= Attributes::AttrOPSIZE as u16;
                    },
                    vex if vex == VexPrefixx86::VexF3 as u8=>{
                        *attributes |= Attributes::AttrXS as u16;
                    },
                    vex if vex == VexPrefixx86::VexF2 as u8=>{
                        *attributes |= Attributes::AttrXD as u16;
                    },
                    _=>{},
                }
                if accessor!(VexL_3_3: _instr.prefix.vex_prefix[2]) != 0 {
                    *attributes |= Attributes::AttrVEXL as u16;
                }
            },
            VexExType::Vex2B=>{
                match accessor!(VexPP_2_2: _instr.prefix.vex_prefix[1]) {
                    vex if vex == VexPrefixx86::Vex66 as u8=>{
                        *attributes |= Attributes::AttrOPSIZE as u16;
                    },
                    vex if vex == VexPrefixx86::VexF3 as u8=>{
                        *attributes |= Attributes::AttrXS as u16;
                    },
                    vex if vex == VexPrefixx86::VexF2 as u8=>{
                        *attributes |= Attributes::AttrXD as u16;
                    },
                    _=>{},
                }
                if accessor!(VexL_2_2: _instr.prefix.vex_prefix[1]) != 0 {
                    *attributes |= Attributes::AttrVEXL as u16;
                }
            },
            VexExType::Xop=>{
                match accessor!(XopPP_3_3: _instr.prefix.vex_prefix[2]) {
                    vex if vex == VexPrefixx86::Vex66 as u8=>{
                        *attributes |= Attributes::AttrOPSIZE as u16;
                    },
                    vex if vex == VexPrefixx86::VexF3 as u8=>{
                        *attributes |= Attributes::AttrXS as u16;
                    },
                    vex if vex == VexPrefixx86::VexF2 as u8=>{
                        *attributes |= Attributes::AttrXD as u16;
                    },
                    _=>{},
                }
                if accessor!(XopL_3_3: _instr.prefix.vex_prefix[2]) != 0 {
                    *attributes |= Attributes::AttrVEXL as u16;
                }
            },
            _=>{},
        }
    } else {
        // 16bit mode and check prefix
        if _instr.mode != Modex86::Mode16 && verify_prefix(_instr, 0x66){
            disasm_debug!("\tAttributes::AttrOPSIZE applied");
            *attributes |= Attributes::AttrOPSIZE as u16;
        } else if verify_prefix(_instr, 0x67){
            *attributes |= Attributes::AttrADSIZE as u16;
        } else if _instr.mode != Modex86::Mode16 && verify_prefix(_instr, 0xF3){
            *attributes |= Attributes::AttrXS as u16;
        } else if _instr.mode != Modex86::Mode16 && verify_prefix(_instr, 0xF2){
            *attributes |= Attributes::AttrXD as u16;
        }
    }
}

fn eq16bit(left: &u16, right: &u16) -> bool 
{
    disasm_debug!("eq16bit(left: {:?}, right: {:?})", *left, *right);
    let _index: &u16 = &(INSTRUCTION_LOOKUPSX86[*left as usize].bit16_eq);
    if *_index != 0 {
        if INSTRUCTION_LOOKUPSX86[(*_index-1) as usize].op_id_pair == *right {
            return true;
        }
    }
    return false;
}

/// handling for 16-bit adsize
fn handle_16bit_adsize(
    _instr: &mut Instructionx86, 
    _attr: &mut u16,
    _opcode: &u16,
    _instruction_index: &mut u16,
    _instruction_specifier: &mut u16) -> bool 
{
    // handling for 16-bit
    if _instr.mode == Modex86::Mode16 && *_opcode == 0xE3
    {
        disasm_debug!("handle_16bit_adsize() handling for 16-bit adsize");
        *_instruction_specifier = INSTRUCTION_LOOKUPSX86[*_instruction_index as usize].inst_specifier;
        //Check for Ii8PCRel
        if DISASMX86_OPERANDSETS[*_instruction_specifier as usize][0].encodetype == OperandTypex86::TYPEREL8{
            disasm_debug!("\tCheck for Ii8PCRel");
            *_attr ^= Attributes::AttrADSIZE as u16;
            if !get_instruction_index(_instr, &_attr, _instruction_index){ return false; }      
        }
    }
    return true;
}

/// table fix up for 16 bit opsize
fn handle_16bit_opsize(
    _instr: &mut Instructionx86, 
    _attr: &mut u16,
    _opcode: &u16,
    _instruction_index: &mut u16,
    _instruction_specifier: &mut u16) -> bool 
{
    let prefix_flags = _instr.prefix.prefix_flags;

    if (_instr.mode == Modex86::Mode16 || 
        ((prefix_flags & PrefixMaskx86::OPSize as u32) != 0)) &&
        (*_attr & Attributes::AttrOPSIZE as u16) == 0
    {
        disasm_debug!("handle_16bit_opsize() table fix up 16-bit opsize");
        let attributes: u16 = *_attr | Attributes::AttrOPSIZE as u16;
        let mut instr_index_opsize: u16 = 0;
        
        // ModRM required with OpSize
        if !get_instruction_index(_instr, &attributes, &mut instr_index_opsize){
            return true; 
        }
        disasm_debug!("\t16-bit ModRM required with OpSize");
        if eq16bit(_instruction_index, &instr_index_opsize) && 
            (_instr.mode == Modex86::Mode16) ^ 
            ((prefix_flags & PrefixMaskx86::OPSize as u32) != 0)
        {
            *_instruction_index=instr_index_opsize;
            *_instruction_specifier=INSTRUCTION_LOOKUPSX86[instr_index_opsize as usize].inst_specifier;
        }
    }
    disasm_debug!("\tnot eq16bit");
    if *_instruction_index == 0 {
        return false;
    }
    return true;
}

/// Ghetto way for handling 0x90 should be XCHG if REX.b is set
fn handle_xchng_nop(
    _instr: &mut Instructionx86, 
    _attr: &mut u16,
    _opcode: &u16,
    _instruction_index: &mut u16,
    _instruction_specifier: &mut u16) -> bool
{
    disasm_debug!("handle_xchng_nop()");
    let _prefix_flags = _instr.prefix.prefix_flags;
    if (_instr.opcode.kind == OpcodeTypex86::OneByte) && 
        (*_opcode == 0x90)
    {
        if (_prefix_flags & PrefixFlagsx86::Rex as u32) != 0 
        { 
            _instr.opcode.data[0] = 0x91;
            let mut instr_index_opcode: u16 = 0;
            if !get_instruction_index(_instr, &_attr, &mut instr_index_opcode){ 
                _instr.opcode.data[0] = 0x90;
                return true; 
            }
            disasm_debug!("\thandle one byte instructions for xchng");
            _instr.opcode.data[0] = 0x90;
            *_instruction_index=instr_index_opcode;
            *_instruction_specifier = INSTRUCTION_LOOKUPSX86[instr_index_opcode as usize].inst_specifier;    
        }
    }
    if *_instruction_index == 0 {
        return false;
    }
    return true;
}

pub fn instruction_index_read(_instr: &mut Instructionx86) -> bool
{
    disasm_debug!("instruction_index_read()");
    let mut attributes: u16 = Attributes::AttrNone as u16;
    let mut instruction_index: u16 = 0;
    let mut instruction_specifier: u16 = 0;
    let mut _opcode: u16 = 0;

    // set mode
    if _instr.mode == Modex86::Mode64 {
        attributes |= Attributes::Attr64BIT as u16;
    }
    
    // match vex type
    instr_vex_prefix(_instr, &mut attributes);
    
    // rex prefix
    if _instr.prefix.kind[PrefixMaskx86::Rex as usize] & 0x08 != 0 {
        attributes |= Attributes::AttrREXW as u16;
    }

    // get id with mask
    if !get_instruction_index(_instr, &attributes, &mut instruction_index){ return false; }

    // get opcode
    _opcode = _instr.opcode.data[0] as u16;
    if _instr.opcode.size == 2 {
        _opcode = _instr.opcode.data[1] as u16;
    }
    // fix call and jmp instructions for 64bit and 0x66 prefix
    if _instr.mode == Modex86::Mode64 {
        if _instr.prefix.kind[PrefixMaskx86::OPSize as usize] != 0 {
            match _opcode {
                0xE8 | 0xE9=>{
                    disasm_debug!("\tCALL or JMP with opsize 0x66 and 64bit");
                    attributes ^= Attributes::AttrOPSIZE as u16;
                    if !get_instruction_index(_instr, &attributes, &mut instruction_index){ return false; }
                },
                _=>{},
            }
        }
    }

    // handling for 16-bit adsize
    if !handle_16bit_adsize(
        _instr,
        &mut attributes,
        &_opcode,
        &mut instruction_index,
        &mut instruction_specifier)
    { 
        return false;
    }
    
    // table fix up for 16 bit opsize
    if !handle_16bit_opsize(
        _instr, 
        &mut attributes,
        &_opcode,
        &mut instruction_index,
        &mut instruction_specifier) 
    {
        return false;
    }

    // Ghetto way for handling 0x90 should be XCHG if REX.b is set
    if !handle_xchng_nop(
        _instr, 
        &mut attributes,
        &_opcode,
        &mut instruction_index,
        &mut instruction_specifier) 
    {
        return false;
    }
    _instr.instr_index=instruction_index;
    if instruction_specifier != 0{
        _instr.instr_spec = Some(instruction_specifier);
    } else {
        _instr.instr_spec= Some(INSTRUCTION_LOOKUPSX86[instruction_index as usize].inst_specifier);
    }
    disasm_debug!("\tinstruction_index_read::instruction index {:?}", _instr.instr_index);
    disasm_debug!("\tinstruction_index_read::instruction_spec {:?}", _instr.instr_spec);
    return true;
}

macro_rules! to_u16 {
    ($e:expr) =>($e as u16);
}
pub fn check_illegal_prefix(_instr: &mut Instructionx86) -> bool
{
    disasm_debug!("check_illegal_prefix()");
    // Lock
    if (_instr.prefix.prefix_flags & PrefixFlagsx86::Lock as u32) != 0 {
        match _instr.instr_index {
            x if x == to_u16!(Instructionsx86::NOOPL) | 
            // DEC
            to_u16!(Instructionsx86::DEC16m) |
            to_u16!(Instructionsx86::DEC32m) |
            to_u16!(Instructionsx86::DEC6416m) |
            to_u16!(Instructionsx86::DEC6432m) |
            to_u16!(Instructionsx86::DEC64m) |
            to_u16!(Instructionsx86::DEC8m) |
            // ADC
            to_u16!(Instructionsx86::ADC16mi) |
            to_u16!(Instructionsx86::ADC16mi8) |
            to_u16!(Instructionsx86::ADC16mr) |
            to_u16!(Instructionsx86::ADC32mi) |
            to_u16!(Instructionsx86::ADC32mi8) |
            to_u16!(Instructionsx86::ADC32mr) |
            to_u16!(Instructionsx86::ADC64mi32) |
            to_u16!(Instructionsx86::ADC64mi8) |
            to_u16!(Instructionsx86::ADC64mr) |
            to_u16!(Instructionsx86::ADC8mi) |
            to_u16!(Instructionsx86::ADC8mr) |

            // ADD
            to_u16!(Instructionsx86::ADD16mi) |
            to_u16!(Instructionsx86::ADD16mi8) |
            to_u16!(Instructionsx86::ADD16mr) |
            to_u16!(Instructionsx86::ADD32mi) |
            to_u16!(Instructionsx86::ADD32mi8) |
            to_u16!(Instructionsx86::ADD32mr) |
            to_u16!(Instructionsx86::ADD64mi32) |
            to_u16!(Instructionsx86::ADD64mi8) |
            to_u16!(Instructionsx86::ADD64mr) |
            to_u16!(Instructionsx86::ADD8mi) |
            to_u16!(Instructionsx86::ADD8mr) |

            // AND
            to_u16!(Instructionsx86::AND16mi) |
            to_u16!(Instructionsx86::AND16mi8) |
            to_u16!(Instructionsx86::AND16mr) |
            to_u16!(Instructionsx86::AND32mi) |
            to_u16!(Instructionsx86::AND32mi8) |
            to_u16!(Instructionsx86::AND32mr) |
            to_u16!(Instructionsx86::AND64mi32) |
            to_u16!(Instructionsx86::AND64mi8) |
            to_u16!(Instructionsx86::AND64mr) |
            to_u16!(Instructionsx86::AND8mi) |
            to_u16!(Instructionsx86::AND8mr) |

            // BTC
            to_u16!(Instructionsx86::BTC16mi8) |
            to_u16!(Instructionsx86::BTC16mr) |
            to_u16!(Instructionsx86::BTC32mi8) |
            to_u16!(Instructionsx86::BTC32mr) |
            to_u16!(Instructionsx86::BTC64mi8) |
            to_u16!(Instructionsx86::BTC64mr) |

            // BTR
            to_u16!(Instructionsx86::BTR16mi8) |
            to_u16!(Instructionsx86::BTR16mr) |
            to_u16!(Instructionsx86::BTR32mi8) |
            to_u16!(Instructionsx86::BTR32mr) |
            to_u16!(Instructionsx86::BTR64mi8) |
            to_u16!(Instructionsx86::BTR64mr) |

            // BTS
            to_u16!(Instructionsx86::BTS16mi8) |
            to_u16!(Instructionsx86::BTS16mr) |
            to_u16!(Instructionsx86::BTS32mi8) |
            to_u16!(Instructionsx86::BTS32mr) |
            to_u16!(Instructionsx86::BTS64mi8) |
            to_u16!(Instructionsx86::BTS64mr) |

            // CMPXCHG
            to_u16!(Instructionsx86::CMPXCHG16B) |
            to_u16!(Instructionsx86::CMPXCHG16rm) |
            to_u16!(Instructionsx86::CMPXCHG32rm) |
            to_u16!(Instructionsx86::CMPXCHG64rm) |
            to_u16!(Instructionsx86::CMPXCHG8rm) |
            to_u16!(Instructionsx86::CMPXCHG8B) |

            // INC
            to_u16!(Instructionsx86::INC16m) |
            to_u16!(Instructionsx86::INC32m) |
            to_u16!(Instructionsx86::INC6416m) |
            to_u16!(Instructionsx86::INC6432m) |
            to_u16!(Instructionsx86::INC64m) |
            to_u16!(Instructionsx86::INC8m) |

            // NEG
            to_u16!(Instructionsx86::NEG16m) |
            to_u16!(Instructionsx86::NEG32m) |
            to_u16!(Instructionsx86::NEG64m) |
            to_u16!(Instructionsx86::NEG8m) |

            // NOT
            to_u16!(Instructionsx86::NOT16m) |
            to_u16!(Instructionsx86::NOT32m) |
            to_u16!(Instructionsx86::NOT64m) |
            to_u16!(Instructionsx86::NOT8m) |

            // OR
            to_u16!(Instructionsx86::OR16mi) |
            to_u16!(Instructionsx86::OR16mi8) |
            to_u16!(Instructionsx86::OR16mr) |
            to_u16!(Instructionsx86::OR32mi) |
            to_u16!(Instructionsx86::OR32mi8) |
            to_u16!(Instructionsx86::OR32mr) |
            to_u16!(Instructionsx86::OR32mrLocked) |
            to_u16!(Instructionsx86::OR64mi32) |
            to_u16!(Instructionsx86::OR64mi8) |
            to_u16!(Instructionsx86::OR64mr) |
            to_u16!(Instructionsx86::OR8mi) |
            to_u16!(Instructionsx86::OR8mr) |

            // SBB
            to_u16!(Instructionsx86::SBB16mi) |
            to_u16!(Instructionsx86::SBB16mi8) |
            to_u16!(Instructionsx86::SBB16mr) |
            to_u16!(Instructionsx86::SBB32mi) |
            to_u16!(Instructionsx86::SBB32mi8) |
            to_u16!(Instructionsx86::SBB32mr) |
            to_u16!(Instructionsx86::SBB64mi32) |
            to_u16!(Instructionsx86::SBB64mi8) |
            to_u16!(Instructionsx86::SBB64mr) |
            to_u16!(Instructionsx86::SBB8mi) |
            to_u16!(Instructionsx86::SBB8mr) |

            // SUB
            to_u16!(Instructionsx86::SUB16mi) |
            to_u16!(Instructionsx86::SUB16mi8) |
            to_u16!(Instructionsx86::SUB16mr) |
            to_u16!(Instructionsx86::SUB32mi) |
            to_u16!(Instructionsx86::SUB32mi8) |
            to_u16!(Instructionsx86::SUB32mr) |
            to_u16!(Instructionsx86::SUB64mi32) |
            to_u16!(Instructionsx86::SUB64mi8) |
            to_u16!(Instructionsx86::SUB64mr) |
            to_u16!(Instructionsx86::SUB8mi) |
            to_u16!(Instructionsx86::SUB8mr) |

            // XADD
            to_u16!(Instructionsx86::XADD16rm) |
            to_u16!(Instructionsx86::XADD32rm) |
            to_u16!(Instructionsx86::XADD64rm) |
            to_u16!(Instructionsx86::XADD8rm) |

            // XCHG
            to_u16!(Instructionsx86::XCHG16rm) |
            to_u16!(Instructionsx86::XCHG32rm) |
            to_u16!(Instructionsx86::XCHG64rm) |
            to_u16!(Instructionsx86::XCHG8rm) |

            // XOR
            to_u16!(Instructionsx86::XOR16mi) |
            to_u16!(Instructionsx86::XOR16mi8) |
            to_u16!(Instructionsx86::XOR16mr) |
            to_u16!(Instructionsx86::XOR32mi) |
            to_u16!(Instructionsx86::XOR32mi8) |
            to_u16!(Instructionsx86::XOR32mr) |
            to_u16!(Instructionsx86::XOR64mi32) |
            to_u16!(Instructionsx86::XOR64mi8) |
            to_u16!(Instructionsx86::XOR64mr) |
            to_u16!(Instructionsx86::XOR8mi) |
            to_u16!(Instructionsx86::XOR8mr) =>{
                disasm_debug!("\tillegal instruction"); 
                return false;
            },
            _=>{ 
                return true; 
            }
        }
    }

    // Repne 
    if (_instr.prefix.prefix_flags & PrefixFlagsx86::RepNz as u32) != 0 {
        if _instr.opcode.escape_byte2 == 0x0f{
            // Handle special case
            if _instr.instr_index == Instructionsx86::MULPDrr as u16 &&
            match _instr.prefix.kind[PrefixMaskx86::LORep as usize] { 0xF2|0xF3=>true, _=>false }
            {
                disasm_debug!("\tMULPDrr is changed to MULSDrr");
                _instr.instr_index = Instructionsx86::MULSDrr as u16;
                _instr.instr_spec= Some(INSTRUCTION_LOOKUPSX86[_instr.instr_index as usize].inst_specifier);
            }
            _instr.prefix.kind[PrefixMaskx86::LORep as usize] = 0;
            _instr.prefix.location[PrefixMaskx86::LORep as usize] = 0;
        }
    }
    return true;
}

fn operand_immediate(_instr: &mut Instructionx86, _size: u8) -> bool 
{
    disasm_debug!("operand_immediate()");
    if _instr.immediates.is_some() && *(_instr.immediates.as_ref().map(|v| &v.count)).unwrap_or(&0) == 2 {
        disasm_debug!("\talready consumed maximum immediates");
        return false;
    }

    let current_location = _instr.cursor - _instr.start;
    let mut size = _size;
    if size == 0 {
        size = _instr.size.immediate;
    } else {
        _instr.size.immediate = size;
    };

    let imm: i64 = match size {
        1 => {
            disasm_debug!("get_int::<u8>");
            match get_int::<u8>(_instr) {
                Some(value) => value as i64,
                None => { return false; }
            }
        },
        2 => {
            disasm_debug!("get_int::<u16>");
            match get_int::<u16>(_instr) {
                Some(value) => value as i64,
                None => { return false; }
            }
        },
        4 => {
            disasm_debug!("get_int::<u32>");
            match get_int::<u32>(_instr) {
                Some(value) => value as i64,
                None => { return false; }
            }
        },
        8 => {
            disasm_debug!("get_int::<u64>");
            match get_int::<u64>(_instr) {
                Some(value) => value as i64,
                None => { return false; }
            }
        },
        _ => {
            disasm_debug!("\tunknown size");
            return false;
        },
    };

    if _instr.immediates.is_none() {
        _instr.immediates = Some(Immediatex86{..Default::default()});
    }
    match _instr.immediates {
        Some(ref mut im) => {

            im.data[im.count as usize] = imm;
            im.offset[im.count as usize] = current_location as u8;
            im.count += 1
        },
        None => {},
    }

    return true;
}
fn operand_register(_instr: &mut Instructionx86, _size: u8) -> bool 
{
    disasm_debug!("operand_register()");
    let mut reg_size = _size;
    if reg_size == 0 {
        reg_size = _instr.size.register;
    }
    _instr.operand_size = reg_size as u16;

    let _rex_prefix = _instr.prefix.kind[PrefixMaskx86::Rex as usize];
    disasm_debug!("\topcode data {:?}", _instr.opcode.data);
    disasm_debug!("\topcode size {:?}",_instr.opcode.size);
    let op_size: usize = (_instr.opcode.size - 1) as usize;
    let mut _opcode = _instr.opcode.data[op_size] as u16;
    disasm_debug!("\topcode {:?}", _opcode);
    
    
    match reg_size{
        1=>{
            if _instr.register.is_none(){
                _instr.register = Some(Registerx86{..Default::default()});
            }
            match _instr.register{
                Some(ref mut reg)=>{
                    reg.opcode_data = AllRegisters::AL as u8 +
                                ((accessor!(rexb: _rex_prefix) << 3) | 
                                (_opcode & 7) as u8);
                    if _rex_prefix != 0 && 
                    reg.opcode_data >= AllRegisters::AL as u8 + 0x4 &&
                    reg.opcode_data < AllRegisters::AL as u8 + 0x8 
                    {
                        reg.opcode_data = AllRegisters::SPL as u8 +
                         (reg.opcode_data - AllRegisters::AL as u8 -4);
                    }
                },
                None=>{},
            }
        },
        2=>{
            if _instr.register.is_none(){
                _instr.register = Some(Registerx86{..Default::default()});
            }
            match _instr.register{
                Some(ref mut reg)=>{
                    reg.opcode_data = AllRegisters::AX as u8 + 
                                ((accessor!(rexb: _rex_prefix) << 3) | 
                                (_opcode & 7) as u8);
                },
                None=>{},
            }
        },
        4=>{
            if _instr.register.is_none(){
                _instr.register = Some(Registerx86{..Default::default()});
            }
            match _instr.register{
                Some(ref mut reg)=>{
                    reg.opcode_data = AllRegisters::EAX as u8 + 
                                ((accessor!(rexb: _rex_prefix) << 3) | 
                                (_opcode & 7) as u8);
                },
                None=>{},
            }
        },
        8=>{
            if _instr.register.is_none(){
                _instr.register = Some(Registerx86{..Default::default()});
            }
            match _instr.register{
                Some(ref mut reg)=>{
                    reg.opcode_data = AllRegisters::RAX as u8 + 
                                ((accessor!(rexb: _rex_prefix) << 3) | 
                                (_opcode & 7) as u8);
                },
                None=>{},
            }
        },
        _=>{
            return false;
        },
    }
    return true;
}
fn read_register_mask(_instr: &mut Instructionx86) -> bool{

    disasm_debug!("read_register_mask()");
    if _instr.prefix.vex_type != VexExType::EVex {
        return false;
    }
    if _instr.register.is_none(){
        _instr.register = Some(Registerx86{..Default::default()});
    }
    match _instr.register{
        Some(ref mut reg)=>{
            reg.mask = accessor!(EVexAAA_4_4: _instr.prefix.vex_prefix[3]);
        },
        None=>{},
    }
    return true;
}



fn get_reg_by_encoding_type(
    _instr: &mut Instructionx86,
    _type: &OperandTypex86,
    _index: &mut u16,
    _base: u16,
    _reg_type: RegType) -> bool
{
    disasm_debug!("get_reg_by_encoding_type()");
    match *_type{
        OperandTypex86::TYPER8=>{_instr.operand_size=1},
        OperandTypex86::TYPER16=>{_instr.operand_size=2},
        OperandTypex86::TYPER32=>{_instr.operand_size=4},
        OperandTypex86::TYPER64=>{_instr.operand_size=8},
        OperandTypex86::TYPEMM=>{_instr.operand_size=2},
        OperandTypex86::TYPEMM32=>{_instr.operand_size=4},
        OperandTypex86::TYPEMM64=>{_instr.operand_size=8},
        OperandTypex86::TYPEXMM=>{_instr.operand_size=2},
        OperandTypex86::TYPEXMM32=>{_instr.operand_size=4},
        OperandTypex86::TYPEXMM64=>{_instr.operand_size=8},
        OperandTypex86::TYPEXMM128=>{_instr.operand_size=16},
        OperandTypex86::TYPEXMM256=>{_instr.operand_size=32},
        OperandTypex86::TYPEXMM512=>{_instr.operand_size=64},
        OperandTypex86::TYPECONTROLREG=>{_instr.operand_size=4},
        _=>{},
    }
    match *_type{
        OperandTypex86::TYPER8=>{
            if (_instr.prefix.prefix_flags &
            PrefixFlagsx86::Rex as u32) != 0 &&
            *_index >= 4 && *_index <= 7
            { 
                *_index = AllRegisters::SPL as u16 + (*_index-4);
            } else {
                *_index = AllRegisters::AL as u16 + *_index;
            }
        },
        OperandTypex86::TYPER16=>{
            *_index = AllRegisters::AX as u16 + *_index;
        },
        OperandTypex86::TYPER32=>{
            match _reg_type{
                RegType::AllRegisters=>{
                    *_index = AllRegisters::EAX as u16 + *_index;
                },
                RegType::EABases=>{
                    *_index = AllRegisters::EAX as u16 + *_index;
                },
            }
        },
        OperandTypex86::TYPER64=>{
            match _reg_type{
                RegType::AllRegisters=>{
                    *_index = AllRegisters::RAX as u16 + *_index;
                },
                RegType::EABases=>{
                    *_index = AllRegisters::RAX as u16 + *_index;
                },
            }
        },
        OperandTypex86::TYPEMM |
        OperandTypex86::TYPEMM32 |
        OperandTypex86::TYPEMM64=>{
            match _reg_type{
                RegType::AllRegisters=>{
                    *_index = AllRegisters::MM0 as u16 + (*_index & 7);
                },
                RegType::EABases=>{
                    *_index = AllRegisters::MM0 as u16 + (*_index & 7);
                },
            }
            
        },
        OperandTypex86::TYPEXMM |
        OperandTypex86::TYPEXMM32 |
        OperandTypex86::TYPEXMM64 |
        OperandTypex86::TYPEXMM128=>{
            *_index = AllRegisters::XMM0 as u16 + *_index;
        },
        OperandTypex86::TYPEXMM256=>{
            *_index = AllRegisters::YMM0 as u16 + *_index;
        },
        OperandTypex86::TYPEXMM512=>{
            *_index = AllRegisters::ZMM0 as u16 + *_index;
        },
        OperandTypex86::TYPEVK1 |
        OperandTypex86::TYPEVK8 |
        OperandTypex86::TYPEVK16=>{
            if *_index > 7 {
                return false;
            }
            *_index = AllRegisters::K0 as u16 + *_index;
        },
        OperandTypex86::TYPESEGMENTREG=>{
            if *_index > 5 {
                return false;
            }
            *_index = AllRegisters::ES as u16 + *_index;
        },
        OperandTypex86::TYPEDEBUGREG=>{
            if *_index > 7 {
                return false;
            }
            *_index = AllRegisters::DR0 as u16 + *_index;
        },
        OperandTypex86::TYPECONTROLREG=>{
            *_index = AllRegisters::CR0 as u16 + *_index;
        },
        OperandTypex86::TYPERv=>{
            *_index=*_index + _base as u16;
        },
        _=>{ 
            *_index = 0;
            disasm_debug!("\tOperandTypex86 unknown");
            return true; 
        },
    }
    
    return true;
}

/// get the register based on the specifier
fn read_register_specifier(
    _instr: &mut Instructionx86,
    _set: &OperandSetPair) -> bool
{
    disasm_debug!("read_register_specifier(_set: {:?}", _set);
    let mut index: u16;
    let mut base; 
    match _set.encoding{
        OperandEncodingx86::ENCODINGVVVV=>{
            if _instr.register.is_none(){
                _instr.register = Some(Registerx86{..Default::default()});
            }
            disasm_debug!("\tOperandEncodingx86::ENCODINGVVVV");
            index = as_ref!(_instr, register, vvvv) as u16;
            base = as_ref!(_instr, mod_rm, base_reg);
            if !get_reg_by_encoding_type(
                _instr,
                &_set.encodetype,
                &mut index,
                base,
                RegType::AllRegisters){ return false; }
            
            match _instr.register{
                Some(ref mut reg)=>{
                    reg.vvvv = index as u8;
                },
                None=>{},
            }
        },
        OperandEncodingx86::ENCODINGREG=>{
            if _instr.register.is_none(){
                _instr.register = Some(Registerx86{..Default::default()});
            }
            disasm_debug!("\tOperandEncodingx86::ENCODINGREG");
            index = (as_ref!(_instr, register, data) as u16) - as_ref!(_instr, mod_rm, base_reg);
            disasm_debug!("\tindex {:?}", index);
            base = as_ref!(_instr, mod_rm, base_reg);
            disasm_debug!("\tbase {:?}", base);
            if !get_reg_by_encoding_type(
                _instr,
                &_set.encodetype,
                &mut index,
                base,
                RegType::AllRegisters){ return false; }
            
            match _instr.register{
                Some(ref mut reg)=>{
                    reg.data = index as u8;
                },
                None=>{},
            }
        },
        OperandEncodingx86::ENCODINGRM |
        OperandEncodingx86::ENCODINGRMCD2 |
        OperandEncodingx86::ENCODINGRMCD4 |
        OperandEncodingx86::ENCODINGRMCD8 |
        OperandEncodingx86::ENCODINGRMCD16 |
        OperandEncodingx86::ENCODINGRMCD32 |
        OperandEncodingx86::ENCODINGRMCD64 =>{
            if _instr.register.is_none(){
                _instr.register = Some(Registerx86{..Default::default()});
            }
            disasm_debug!("\tOperandEncodingx86::ENCODINGRM");
            disasm_debug!("\tbase_ea {:?}", as_ref!(_instr, mod_rm, base_ea));
            disasm_debug!("\tbase_ea_reg {:?}", as_ref!(_instr, mod_rm, base_ea_reg));
            if as_ref!(_instr, mod_rm, base_ea) >= as_ref!(_instr, mod_rm, base_ea_reg){
                index = as_ref!(_instr, mod_rm, base_ea) - as_ref!(_instr, mod_rm, base_ea_reg);
                disasm_debug!("\tindex {:?}", index); 
                base = as_ref!(_instr, mod_rm, base_ea_reg);
                if base >= EABases::Max as u16{
                    disasm_debug!("EABases::Max is subtracted");
                    base = base - EABases::Max as u16;
                }
                if !get_reg_by_encoding_type(
                    _instr,
                    &_set.encodetype,
                    &mut index,
                    base,
                    RegType::EABases){ return false; }
                if index != 0 {
                    match _instr.mod_rm{
                        Some(ref mut md)=>{
                            md.base_ea = index as u16;
                        },
                        None=>{},
                    }
                }  
            }
        },
        _=>{},
    }
    return true;
}

fn handle_vvvv(_instr: &mut Instructionx86) -> bool{
    disasm_debug!("handle_vvvv()");
    let mut _vvvv: u8 = 0;

    match _instr.prefix.vex_type{
        VexExType::EVex=>{
            disasm_debug!("\tvvvv EVex");
            _vvvv = accessor!(EVexV2_4_4: _instr.prefix.vex_prefix[3]) << 4 | 
            accessor!(EVexVVVV_3_4: _instr.prefix.vex_prefix[2]);
            disasm_debug!("\tvvvv is {:?}",_vvvv);
        },
        VexExType::Vex3B=>{
            disasm_debug!("\tvvvv Vex3B");
            _vvvv = accessor!(VexVVVV_3_3: _instr.prefix.vex_prefix[2]); 
        },
        VexExType::Vex2B=>{
            disasm_debug!("\tvvvv Vex2B");
            _vvvv = accessor!(VexVVVV_2_2: _instr.prefix.vex_prefix[1]);
        },
        VexExType::Xop=>{
            disasm_debug!("\tvvvv Xop");
            _vvvv = accessor!(XopVVVV_3_3: _instr.prefix.vex_prefix[2]);
        },
        _=>{ 
            disasm_debug!("\tvex type is not applicable");
            return false; 
        }
    }
    if _instr.mode != Modex86::Mode64 {
        _vvvv &= 0x7;
    }
    if _instr.register.is_none(){
        _instr.register = Some(Registerx86{..Default::default()});
    }
    match _instr.register{
        Some(ref mut reg)=>{
            reg.vvvv = _vvvv;
            disasm_debug!("\tnew vvvv is {:?}", reg.vvvv);
        },
        None=>{},
    }
    return true;
}
// read all the operands
pub fn operand_read(_instr: &mut Instructionx86) -> bool
{
    disasm_debug!("operand_read()");
    // handle VVVV
    let is_vvvv = handle_vvvv(_instr);
    let mut valid_vvvv = is_vvvv && (_instr.register.is_some() && as_ref!(_instr, register, vvvv) != 0);
    let mut split_imm = false;
    for index in 0..6 { // Maxium operands is 6
        let spec: usize = match _instr.instr_spec { Some(ref s)=>*s as usize, None=>0 };
        match DISASMX86_OPERANDSETS[spec][index].encoding{
            OperandEncodingx86::ENCODINGNONE | 
            OperandEncodingx86::ENCODINGSI | 
            OperandEncodingx86::ENCODINGDI =>{disasm_debug!("\tENCODINGNONE");},
            OperandEncodingx86::ENCODINGREG |
            OperandEncodingx86::ENCODINGRM |
            OperandEncodingx86::ENCODINGRMCD2 |
            OperandEncodingx86::ENCODINGRMCD4 |
            OperandEncodingx86::ENCODINGRMCD8 |
            OperandEncodingx86::ENCODINGRMCD16 |
            OperandEncodingx86::ENCODINGRMCD32 |
            OperandEncodingx86::ENCODINGRMCD64 =>{
                disasm_debug!("\toperand_read::{:?}", DISASMX86_OPERANDSETS[spec][index].encoding);
                // readmodrm
                if !opcode_read_modrm(_instr){
                    return false;
                }
                // get the register based on the specifier
                if !read_register_specifier(
                    _instr,
                    &(DISASMX86_OPERANDSETS[spec][index]))
                {
                    return false;
                }
                //AVX512 compressed displacement scaling factor
                if DISASMX86_OPERANDSETS[spec][index].encoding != OperandEncodingx86::ENCODINGREG &&
                as_ref!(_instr, mod_rm, displacement_ea) == EADisplacement::Size8 {
                    match _instr.mod_rm {
                        Some(ref mut mod_rm)=>{
                            match mod_rm.displacement{
                                Some( ref mut disp ) => {
                                    disp.data *= 1 << ((DISASMX86_OPERANDSETS[spec][index].encoding) as u16 - OperandEncodingx86::ENCODINGRM as u16) as u8;
                                    disasm_debug!("\tAVX512 displacement is {:?}", disp.data);
                                },
                                None => {}
                            }
                        },
                        None => {},
                    }
                }
            },
            OperandEncodingx86::ENCODINGCB |
            OperandEncodingx86::ENCODINGCW |
            OperandEncodingx86::ENCODINGCD |
            OperandEncodingx86::ENCODINGCP |
            OperandEncodingx86::ENCODINGCO |
            OperandEncodingx86::ENCODINGCT =>{
                // relative jump fixups
                // cb, cw, cd, cp, co, ct — A 1-byte (cb), 2-byte (cw), 4-byte (cd), 6-byte (cp), 8-byte (co) or 10-byte (ct) valuefollowing the opcode. 
                // This value is used to specify a code offset and possibly a new value for the code segmentregister.
                disasm_debug!("\tCode offset encodings");
                return false;
            },
            //The opcode determines if the operand is a signed value.
            OperandEncodingx86::ENCODINGIB =>{
                disasm_debug!("\tENCODINGIB");
                //TODO Hack for immediates split
                if split_imm {
                    if _instr.immediates.is_none(){
                        _instr.immediates = Some(Immediatex86{..Default::default()});
                    }
                    match _instr.immediates{
                        Some( ref mut im ) => {
                            im.data[im.count as usize] = im.data[im.count as usize -1] & 0xf;
                            im.count+=1;
                        },
                        None => {},
                    }
                }
                // readimmediate
                if !operand_immediate(_instr, 1){
                    disasm_debug!("\tfailed to consume immediates");
                    return false;
                }
                //Operandsets
                if DISASMX86_OPERANDSETS[spec][index].encodetype == OperandTypex86::TYPEXMM128 ||
                DISASMX86_OPERANDSETS[spec][index].encodetype == OperandTypex86::TYPEXMM256 {
                    split_imm = true;
                }
            },
            OperandEncodingx86::ENCODINGIW =>{
                disasm_debug!("\tENCODINGIW");
                // readimmediate
                if !operand_immediate(_instr, 2){
                    return false;
                }
            },
            OperandEncodingx86::ENCODINGID =>{
                disasm_debug!("\tENCODINGID");
                // readimmediate
                if !operand_immediate(_instr, 4){
                    return false;
                }
            },
            OperandEncodingx86::ENCODINGIO =>{
                disasm_debug!("\tENCODINGIO");
                // readimmediate
                if !operand_immediate(_instr, 8){
                    return false;
                }
            },
            OperandEncodingx86::ENCODINGIv =>{
                disasm_debug!("\tENCODINGIv");
                //readimmediate
                let mut size: u8 = 0;
                if _instr.immediates.is_some(){
                    size = _instr.size.immediate;
                }
                if !operand_immediate(_instr, size){
                    return false;
                }
            },
            OperandEncodingx86::ENCODINGIa =>{
                disasm_debug!("\tENCODINGIa");
                //readimmediate
                let size = _instr.size.address;
                if !operand_immediate(_instr, size){
                    return false;
                }
            },
            // Indicated the lower 3 bits of the opcode byte is used to encode the register operand without a modR/M byte.
            OperandEncodingx86::ENCODINGRB =>{
                disasm_debug!("\tENCODINGRB");
                // readopcodereg
                if !operand_register(_instr, 1){
                    return false;
                }
            },
            OperandEncodingx86::ENCODINGRW =>{
                disasm_debug!("\tENCODINGRW");
               // readopcodereg
                if !operand_register(_instr, 2){
                    return false;
                }
            },
            OperandEncodingx86::ENCODINGRD =>{
                disasm_debug!("\tENCODINGRD");
                // readopcodereg
                if !operand_register(_instr, 4){
                    return false;
                }
            },
            OperandEncodingx86::ENCODINGRO =>{
                disasm_debug!("\tENCODINGRO");
                // readopcodereg
                if !operand_register(_instr, 8){
                    return false;
                }
            },
            OperandEncodingx86::ENCODINGRv =>{
                disasm_debug!("ENCODINGRv");
                // readopcodereg
                if !operand_register(_instr, 0){
                    return false;
                }
            },
            OperandEncodingx86::ENCODINGFP =>{},
            OperandEncodingx86::ENCODINGVVVV =>{
                disasm_debug!("\tENCODINGVVVV");
                valid_vvvv = false;
                if valid_vvvv{ 
                    disasm_debug!("\tvvvv is not valid");
                    return false; 
                }
                // get the register based on the specifier
                if !read_register_specifier(
                    _instr,
                    &(DISASMX86_OPERANDSETS[spec][index]))
                {
                    return false;
                }
            },
            OperandEncodingx86::ENCODINGWRITEMASK =>{
                disasm_debug!("\tENCODINGWRITEMASK");
                // readmaskreg
                if !read_register_mask(_instr){
                   return false;
               }
            },
            OperandEncodingx86::ENCODINGDUP =>{},
        }
    }
    // check VVVV
    if valid_vvvv{
        disasm_debug!("\tvalid_vvvv is not valid");
        return false;
    }
    return true;
}
