//prefixx86.rs
use arch::x86::archx86::*;
use arch::x86::registersx86::*;

/// Prefix flags.
pub enum PrefixFlagsx86
{
    /// Empty flags indicator
    FlagsNone = 0, 
    Lock = 1 << 4, 
    /// REPNZ prefix for string instructions only - means an instruction can follow it.
    RepNz = 1 << 5, 
    /// REP prefix for string instructions only - means an instruction can follow it.
    Rep = 1 << 6, 
    /// CS override prefix.
    SegCS = 1 << 7, 
    /// SS override prefix.
    SegSS = 1 << 8, 
    /// DS override prefix.
    SegDS = 1 << 9, 
    /// ES override prefix.
    SegES = 1 << 10, 
    /// FS override prefix.
    SegFS = 1 << 11, 
    /// GS override prefix.
    SegGS = 1 << 12, 
    /// Switch operand size from 32 to 16 and vice versa.
    OPSize = 1 << 13, 
    /// Switch address size from 32 to 16 and vice versa.
    ADDRSize = 1 << 14, 
    /// Indicates the instruction must be REX prefixed in order to use 64 bits operands.
    Rex = 1 << 25, 
    /// Indicates that instruction is encoded with a VEX prefix.
    Vex = 1 << 29, 
}

/// Prefix masks.
pub enum PrefixMaskx86
{
    Rex = 0,
    LORep = 1, 
    Seg = 2,
    OPSize = 3 , 
    ADDRSize = 4,
    MAXsize = 5,
}

/// Vex prefix code values for the VEX pp (implied legacy prefix) field and EVEX.pp.
pub enum VexPrefixx86
{
    VexNone = 0x0,
    Vex66 = 0x1,
    VexF3 = 0x2,
    VexF2 = 0x3,
}

/// Vex Extention Type.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum VexExType
{
    NoXop = 0x0,
    Vex2B = 0x1,
    Vex3B = 0x2,
    EVex = 0x3,
    Xop = 0x4,
}

/// Check if byte is a valid prefix.
fn prefix_check(
    byte: &u8, 
    mode: &Modex86) -> bool
{
    disasm_debug!("prefix_check(byte: {:?})", byte);
    match *byte
    {
        0x40...0x4f => match *mode{ Modex86::Mode64 => return true, _=> return false, }, /* REX */
        0x26 => return true, /* ES */
        0x2e => return true, /* CS */
        0x36 => return true, /* SS */
        0x3e => return true, /* DS */
        0x64 => return true, /* FS */
        0x65 => return true, /* GS */
        0x66 => return true, /* OP Size */
        0x67 => return true, /* ADDR */
        0xC5 => return true, /* VEX2b */
        0xC4 => return true, /* VEX3b */
        0xF0 => return true, /* Lock */
        0xF2 => return true, /* REPNE/REPNZ */
        0xF3 => return true, /* REP or REPE/REPZ */
        _ => return false,
    }
}

/// Check if prefix requires to the set xAquireRelease.
fn prefix_is_xacquirerelease(
    byte: &u8, 
    nbyte: &mut u8, 
    _instr: &mut Instructionx86) -> bool 
{
    disasm_debug!("prefix_is_xacquirerelease(byte: {:?}, nbyte: {:?})", byte, nbyte);
    let mut x_acquire_release: bool = false;
    if ( *byte == 0xF2 as u8 || 
         *byte == 0xF3 as u8 ) && 
       ( *nbyte & 0xfe == 0x86 ||
         *nbyte & 0xf8 == 0x90){
         x_acquire_release = true;
       }
    if *byte == 0xF3 as u8 && 
       ( *nbyte == 0x88 ||
         *nbyte == 0x89 ||
         *nbyte == 0xc6 ||
         *nbyte == 0xc7){
         x_acquire_release = true;
       }
    // 64bt mode
    match _instr.mode {
        Modex86::Mode64 => {
            if (*nbyte & 0xf0) == 0x40 {
               if !get_byte(_instr, nbyte) { return false; }
               if !peek_byte(_instr, nbyte) { return false; }
               release_byte(_instr);
            }
        }
        _=> {}
    }
    return x_acquire_release;
}

/// Set the flag and prefix locations
fn prefix_set_state(
    _instr: &mut Instructionx86, 
    byte: &u8, 
    location: &u64, 
    flag: u32, 
    mask: usize)
{
    disasm_debug!("prefix_set_state(byte: {:?}, location: {:?}, mask: {:?})", byte, location, mask);
    _instr.prefix.prefix_flags = _instr.prefix.prefix_flags | flag;
    _instr.prefix.kind[mask] = *byte;
    _instr.prefix.location[mask] = *location;
}

/// Remove replicating bytes in the predfix.
fn prefix_elim_dupe_bytesx64(
    _instr: &mut Instructionx86, 
    byte: &mut u8) -> bool
{
    disasm_debug!("prefix_elim_dupe_bytesx64()");
    if _instr.mode==Modex86::Mode64 {
        let _prefix_location = _instr.cursor;
        if !get_byte(_instr, byte){ return false; }
        if (*byte & 0xf0) == 0x40 {
            loop {
                if !peek_byte(_instr, byte){ return false; }   
                if (*byte & 0xf0) == 0x40 {
                    // another REX prefix
                    if !get_byte(_instr, byte){ return false; }
                } else {
                    break;
                }
            }

            match *byte {
                0xf2 |  /* REPNE/REPNZ */
                0xf3 |  /* REP or REPE/REPZ */
                0xf0 |  /* LOCK */
                0x2e |  /* CS segment override -OR- Branch not taken */
                0x36 |  /* SS segment override -OR- Branch taken */
                0x3e |  /* DS segment override */
                0x26 |  /* ES segment override */
                0x64 |  /* FS segment override */
                0x65 |  /* GS segment override */
                0x66 |  /* Operand-size override */
                0x67 => {},/* Address-size override */
                _=> release_byte(_instr),  /* Not a prefix byte */
            }
            disasm_debug!("\tduplicate prefix byte {:?}", *byte);
        } else {
            release_byte(_instr);
        }
    }
    
    return true; 
}

/// Set the flag and location for all applicable prefixes.
fn prefix_populate_states(
    _instr: &mut Instructionx86, 
    byte: &u8, 
    location: &u64, 
    is_prefix: &mut bool,
    has_opsize: &mut bool,
    has_adsize: &mut bool)
{
    disasm_debug!("prefix_populate_states(byte: {:x})", *byte);
    match *byte
    {
        0x40...0x4f => match _instr.mode{ /* REX */
                Modex86::Mode64 => {
                    let flag = PrefixFlagsx86::Rex as u32;
                    let mask = PrefixMaskx86::Rex as usize;
                    prefix_set_state(_instr, byte, location, flag, mask);
                }, 
                _=> *is_prefix = false,
            },
        0x26 => { /* ES */
            let flag = PrefixFlagsx86::SegES as u32;
            let mask = PrefixMaskx86::Seg as usize;
            prefix_set_state(_instr, byte, location, flag, mask);
            _instr.prefix.segment = Registersx86::ES as u8;
            },
        0x2e => { /* CS */
            let flag = PrefixFlagsx86::SegCS as u32;
            let mask = PrefixMaskx86::Seg as usize;
            prefix_set_state(_instr, byte, location, flag, mask);
            _instr.prefix.segment = Registersx86::CS as u8;
            },
        0x36 => { /* SS */
            let flag = PrefixFlagsx86::SegSS as u32;
            let mask = PrefixMaskx86::Seg as usize;
            prefix_set_state(_instr, byte, location, flag, mask);
            _instr.prefix.segment = Registersx86::SS as u8;
            },
        0x3e => { /* DS */
            let flag = PrefixFlagsx86::SegDS as u32;
            let mask = PrefixMaskx86::Seg as usize;
            prefix_set_state(_instr, byte, location, flag, mask);
            _instr.prefix.segment = Registersx86::DS as u8;
            },
        0x64 => { /* FS */
            let flag = PrefixFlagsx86::SegFS as u32;
            let mask = PrefixMaskx86::Seg as usize;
            prefix_set_state(_instr, byte, location, flag, mask);
            _instr.prefix.segment = Registersx86::FS as u8;
            },
        0x65 => { /* GS */
            let flag = PrefixFlagsx86::SegGS as u32;
            let mask = PrefixMaskx86::Seg as usize;
            prefix_set_state(_instr, byte, location, flag, mask);
            _instr.prefix.segment = Registersx86::GS as u8;
            },
        0x66 => { /* OP Size */
            let flag = PrefixFlagsx86::OPSize as u32;
            let mask = PrefixMaskx86::OPSize as usize;
            prefix_set_state(_instr, byte, location, flag, mask);
            *has_opsize = true;
            },
        0x67 => { /* ADDR */
            let flag = PrefixFlagsx86::ADDRSize as u32;
            let mask = PrefixMaskx86::ADDRSize as usize;
            prefix_set_state(_instr, byte, location, flag, mask);
            *has_adsize = true;
            },
        0xf0 => { /* Lock */
            let flag = PrefixFlagsx86::Lock as u32;
            let mask = PrefixMaskx86::LORep as usize;
            prefix_set_state(_instr, byte, location, flag, mask);
            },
        0xf2 => { /* REPNE/REPNZ */
            let flag = PrefixFlagsx86::RepNz as u32;
            let mask = PrefixMaskx86::LORep as usize;
            prefix_set_state(_instr, byte, location, flag, mask);
            },
        0xf3 => { /* REP or REPE/REPZ */
            let flag = PrefixFlagsx86::Rep as u32;
            let mask = PrefixMaskx86::LORep as usize;
            prefix_set_state(_instr, byte, location, flag, mask);
            },
        _ => *is_prefix = false,
    }
}

/// Extract the EVex byte vector extention prefix from the byte.
/// Use case for b"\x62\xC1\x6D\x48\x62\xCB" vpunpckldq zmm1,zmm2,zmm3
fn prefix_vex62(
    _instr: &mut Instructionx86,
    byte: &u8,
    has_opsize: &mut bool) -> bool
{
    let mut byte1: u8 = 0;
    let mut byte2: u8 = 0;
    if !get_byte(_instr, &mut byte1){ return false; }

    if (_instr.mode == Modex86::Mode64 || 
        (byte1 & 0xc0) == 0xc0) && 
        (!byte1 & 0xc) == 0xc 
    {
        if !peek_byte(_instr, &mut byte2) { return false; }

        if (byte2 & 0x4) == 0x4 
        {
            /* Set the bytes, type */
            let mut byte3: u8 = 0;
            if !get_byte(_instr, &mut byte2){ return false; }
            if !get_byte(_instr, &mut byte3){ return false; }
            _instr.prefix.vex_type = VexExType::EVex;
            _instr.prefix.prefix_flags |= PrefixFlagsx86::Vex as u32;
            _instr.prefix.vex_prefix[0] = *byte;
            _instr.prefix.vex_prefix[1] = byte1;
            _instr.prefix.vex_prefix[2] = byte2;
            _instr.prefix.vex_prefix[3] = byte3;
            /* Simulate Rex */ 
            if _instr.mode == Modex86::Mode64
            {
                _instr.prefix.kind[PrefixMaskx86::Rex as usize] = 0x40 |
                (accessor!(EVexW_3_4: &_instr.prefix.vex_prefix[2]) << 3) |
                (accessor!(EVexR_2_4: &_instr.prefix.vex_prefix[1]) << 2) |
                (accessor!(EVexX_2_4: &_instr.prefix.vex_prefix[1]) << 1) |
                (accessor!(EVexB_2_4: &_instr.prefix.vex_prefix[1]) << 0);
            }
            let pp = accessor!(EVexPP_3_4: &_instr.prefix.vex_prefix[2]);
            if pp == VexPrefixx86::Vex66 as u8
            {
                *has_opsize = true;
            }
        } else {
            release_byte(_instr); 
            release_byte(_instr);
            _instr.prefix.offset=_instr.cursor-2;
        }
            
    } else {
        release_byte(_instr); 
        release_byte(_instr); 
    }
    return true;
}

/// Extract the VEX 2 byte vector extention prefix from the byte.
/// Use case for b"\xC5\xEB\x7D\xCB" vhsubps xmm1,xmm2,xmm3
fn prefix_vex2b(
    _instr: &mut Instructionx86, 
    byte: &u8, 
    has_opsize: &mut bool) -> bool
{
    disasm_debug!("prefix_vex2b(byte: {:?}, has_opsize: {:?})", byte, has_opsize);
    let mut byte1: u8 = 0;
    if !peek_byte(_instr, &mut byte1) { return false; }

    if _instr.mode == Modex86::Mode64 || 
        (byte1 & 0xc0) == 0xc0
    {
        if !get_byte(_instr, &mut byte1){ return false; }
        _instr.prefix.vex_type = VexExType::Vex2B;
        _instr.prefix.prefix_flags |= PrefixFlagsx86::Vex as u32;
        _instr.prefix.vex_prefix[0] = *byte;
        _instr.prefix.vex_prefix[1] = byte1;

        /* Simulate Rex */
        if _instr.mode == Modex86::Mode64
        {
            _instr.prefix.kind[PrefixMaskx86::Rex as usize] = 0x40 | (accessor!(VexR_2_2: &_instr.prefix.vex_prefix[1]) << 2);
        }

        let pp = accessor!(VexPP_2_2: &_instr.prefix.vex_prefix[2]);
        if pp == VexPrefixx86::Vex66 as u8
        {
            *has_opsize = true;
        }
            
    } else {
        release_byte(_instr); /* unconsume byte1 */
        _instr.prefix.offset=_instr.cursor-1;
    } 
    return true;
}

/// Extract the VEX 3 byte vector extention prefix from the byte.
/// Use case for b"\xC4\xE3\x7D\x4B\xEA\x40" vblendvpd ymm5,ymm0,ymm2,ymm4
fn prefix_vex3b(
    _instr: &mut Instructionx86,
    byte: &u8,
    has_opsize: &mut bool) -> bool
{
    disasm_debug!("prefix_vex3b(byte: {:?}, has_opsize: {:?})", byte, has_opsize);
    let mut byte1: u8 = 0;
    if !peek_byte(_instr, &mut byte1) { return false; }

    if _instr.mode == Modex86::Mode64 || 
        (byte1 & 0xc0) == 0xc0
    {
        let mut byte2: u8 = 0;
        if !get_byte(_instr, &mut byte1){ return false; }
        if !get_byte(_instr, &mut byte2){ return false; }
        _instr.prefix.vex_type = VexExType::Vex3B;
        _instr.prefix.prefix_flags |= PrefixFlagsx86::Vex as u32;
        _instr.prefix.vex_prefix[0] = *byte;
        _instr.prefix.vex_prefix[1] = byte1;
        _instr.prefix.vex_prefix[2] = byte2;

        /* Simulate Rex */
        if _instr.mode == Modex86::Mode64
        {
            _instr.prefix.kind[PrefixMaskx86::Rex as usize] = 0x40 |
            (accessor!(VexW_3_3: &_instr.prefix.vex_prefix[2]) << 3) |
            (accessor!(VexR_2_3: &_instr.prefix.vex_prefix[1]) << 2) |
            (accessor!(VexX_2_3: &_instr.prefix.vex_prefix[1]) << 1) |
            (accessor!(VexB_2_3: &_instr.prefix.vex_prefix[1]) << 0);
        }
        let pp = accessor!(VexPP_3_3: &_instr.prefix.vex_prefix[2]);
        if pp == VexPrefixx86::Vex66 as u8
        {
            *has_opsize = true;
        }
            
    } else {
        release_byte(_instr); 
        _instr.prefix.offset=_instr.cursor-1;
    } 
    return true;
}

/// Extract the 3 byte XOP  vector extention prefix from the byte.
fn prefix_vex8f(
    _instr: &mut Instructionx86,
    byte: &u8,
    has_opsize: &mut bool) -> bool
{
    disasm_debug!("prefix_vex8f(byte: {:?}, has_opsize: {:?})", byte, has_opsize);
    let mut byte1: u8 = 0;
    if !peek_byte(_instr, &mut byte1) { return false; }

    if (byte1 & 0x38) != 0x0
    {
        _instr.prefix.offset=_instr.cursor-1;
        let mut byte2: u8 = 0;
        if !get_byte(_instr, &mut byte1){ return false; }
        if !get_byte(_instr, &mut byte2){ return false; }
        _instr.prefix.vex_type = VexExType::Xop;
        _instr.prefix.prefix_flags |= PrefixFlagsx86::Vex as u32;
        _instr.prefix.vex_prefix[0] = *byte;
        _instr.prefix.vex_prefix[1] = byte1;
        _instr.prefix.vex_prefix[2] = byte2;

        /* Simulate Rex */
        if _instr.mode == Modex86::Mode64
        {
            _instr.prefix.kind[PrefixMaskx86::Rex as usize] = 0x40 |
            (accessor!(XopW_3_3: &_instr.prefix.vex_prefix[2]) << 3) |
            (accessor!(XopR_2_3: &_instr.prefix.vex_prefix[1]) << 2) |
            (accessor!(XopX_2_3: &_instr.prefix.vex_prefix[1]) << 1) |
            (accessor!(XopB_2_3: &_instr.prefix.vex_prefix[1]) << 0);
        }
        
        let pp = accessor!(XopPP_3_3: &_instr.prefix.vex_prefix[2]);
        if pp == VexPrefixx86::Vex66 as u8
        {
            *has_opsize = true;
        }
 
    } else {
        release_byte(_instr); /* unconsume byte1 */
        _instr.prefix.offset=_instr.cursor-1;
    } 
    return true;
}

/// Set the sizes from the opcode size
fn prefix_set_instr_sizes(
    _instr: &mut Instructionx86,
    _has_opsize: &bool,
    _has_adsize: &bool) -> bool 
{
    disasm_debug!("prefix_set_instr_sizes(_has_opsize: {:?}, _has_adsize: {:?})", _has_opsize, _has_adsize);
    match _instr.mode{ 
        Modex86::Mode16 =>{
            _instr.size.register = match *_has_opsize { true=>4, false=>2 };
            _instr.size.address = match *_has_adsize { true=>4, false=>2 };
            _instr.size.displacement = match *_has_adsize { true=>4, false=>2 };
            _instr.size.immediate = match *_has_opsize { true=>4, false=>2 };
            _instr.size.imm = match *_has_opsize { true=>4, false=>2 };
            _instr.operand_size = match *_has_opsize { true=>4, false=>2 };
        }, 
        Modex86::Mode32 =>{
            _instr.size.register = match *_has_opsize { true=>2, false=>4};
            _instr.size.address = match *_has_adsize { true=>2, false=>4};
            _instr.size.displacement = match *_has_adsize { true=>2, false=>4};
            _instr.size.immediate = match *_has_opsize { true=>2, false=>4};
            _instr.size.imm = match *_has_opsize { true=>2, false=>4};
            _instr.operand_size = match *_has_opsize { true=>2, false=>4};
        },
        Modex86::Mode64 =>{
            if (_instr.prefix.kind[PrefixMaskx86::Rex as usize] != 0) &&
                (accessor!(rexw: &_instr.prefix.kind[PrefixMaskx86::Rex as usize]) != 0){
                _instr.size.register = 8;
                _instr.size.address = match *_has_adsize { true=>4, false=>8 };
                _instr.size.displacement = 4;
                _instr.size.immediate = 4;
                _instr.size.imm = 4;
            }
            else if _instr.prefix.kind[PrefixMaskx86::Rex as usize] != 0 {
                _instr.size.register = match *_has_opsize { true=>2, false=>4 };
                _instr.size.address = match *_has_adsize { true=>4, false=>8 };
                _instr.size.displacement = match *_has_adsize { true=>2, false=>4 };
                _instr.size.immediate = match *_has_opsize { true=>2, false=>4 };
                _instr.size.imm = match *_has_opsize { true=>2, false=>4 };
                _instr.operand_size = match *_has_opsize { true=>2, false=>4 };
            }
            else {
                _instr.size.register = match *_has_opsize { true=>2, false=>4 };
                _instr.size.address = match *_has_adsize { true=>4, false=>8 };
                _instr.size.displacement = match *_has_adsize { true=>2, false=>4 };
                _instr.size.immediate = match *_has_opsize { true=>2, false=>4 };
                _instr.size.imm = match *_has_opsize { true=>4, false=>8 };
                _instr.operand_size = match *_has_opsize { true=>4, false=>8 };
            }
        },
    }
    return true;
}

/// Track all the prefixes
#[allow(unused_mut,unused_variables)]
pub fn prefix_read(_instr: &mut Instructionx86) -> bool
{
    disasm_debug!("prefix_read()");
    // Get byte
    let mut _prefix_location: u64 = 0;
    let mut byte: u8 = 0;
    let mut nbyte: u8 = 0; // Next byte
    let mut is_prefix: bool = true;
    let mut has_opsize: bool = false;
    let mut has_adsize: bool = false;

    // Populate the prefix states
    while is_prefix {
        // eliminate consecutive redundant REX bytes in front
        if !prefix_elim_dupe_bytesx64(_instr, &mut byte){ 
            disasm_debug!("\tUnable to dedupe consecutive REX bytes");
            return false; 
        }

        _prefix_location = _instr.cursor;
        // get byte
        if !get_byte(_instr, &mut byte){ 
            disasm_debug!("Unable to consume byte");
            return false; 
        }
        // check byte for prefix
        if prefix_check(&byte, &_instr.mode){
            // Get next byte
            if !peek_byte(_instr, &mut nbyte) { 
                disasm_debug!("\tUnable to peek byte");
                return false; 
            }
           
            // check for xAcquireRelease
            if _instr.cursor-1 == _instr.start && match byte { 0xf2 | 0xf3 => true, _=> false}{
                if prefix_is_xacquirerelease(&byte, &mut nbyte, _instr){
                    _instr.prefix.x_acquire_release = true;        
                }
            }
            // Populate the prefix stats
            prefix_populate_states(
                _instr, 
                &byte, 
                &_prefix_location, 
                &mut is_prefix, 
                &mut has_opsize, 
                &mut has_adsize);
        } else {
            is_prefix = false;
        }
    } // End While Loop
   
    // Vex & Opcode checks
    match byte {
        0x62 => { /* vpunpckldq */
            if !prefix_vex62(_instr, &byte, &mut has_opsize){ 
                disasm_debug!("\tCould not retreive Vex62");
                return false; 
            }
        },
        0xc5 => { /* 2 Bytes VEX: */
            if !prefix_vex2b(_instr, &byte, &mut has_opsize){ 
                disasm_debug!("\tCould not retreive Vex2B");
                return false; 
            }
        },
        0xc4 => { /* 3 Bytes VEX: */
            if !prefix_vex3b(_instr, &byte, &mut has_opsize){ 
                disasm_debug!("\tCould not retreive Vex3B");
                return false; 
            }
        },
        0x8f => { /* Three-byte XOP */
            if !prefix_vex8f(_instr, &byte, &mut has_opsize){ 
                disasm_debug!("\tCould not retreive Xop");
                return false; 
            }
        },
        _=>{
            if _instr.mode == Modex86::Mode64 
            {
                if (byte & 0xf0) == 0x40
                {
                    let mut byte1: u8 = 0;
                    loop {
                        if !peek_byte(_instr, &mut byte1) { return false; }
                        if (byte & 0xf0) == 0x40{
                            if !get_byte(_instr, &mut byte){ return false; }
                        } else {
                            break;
                        }
                    }
                    _instr.prefix.kind[PrefixMaskx86::Rex as usize] = byte;
                    _instr.prefix.offset=_instr.cursor-2;
                } else {
                    release_byte(_instr); /* unconsume byte1 */
                    _instr.prefix.offset=_instr.cursor-1;
                }
            } else {
                release_byte(_instr); /* unconsume byte1 */
                _instr.prefix.offset=_instr.cursor-1;
            }
        }
    }
    
    // Instruction Sizing
    if !prefix_set_instr_sizes(_instr, &has_opsize, &has_adsize ){ 
        disasm_debug!("\tCould not populate instruction sizing");
        return false; 
    }
    disasm_debug!("\tprefixes {:?}", _instr.prefix.kind);
    return true;
}
