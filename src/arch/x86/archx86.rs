/// This mod holds all of the functions for writing an instruction for x86
use disasm::*;
use arch::x86::prefixx86::*;
use arch::x86::opcodex86::*;
use arch::x86::operandx86::*;
use arch::x86::disasmtablesx86::*;
use arch::x86::displayx86::*;
use num::{Num, NumCast};
use num::traits::AsPrimitive;
use std::fmt::Debug;

// Enums
#[derive(Debug,PartialEq)]
pub enum OpcodeTypex86 {
    OneByte       = 0,
    TwoByte       = 1,
    ThreeByte38   = 2,
    ThreeByte3A   = 3,
    Xop8Map       = 4,
    Xop9Map       = 5,
    XopAMap       = 6,
    T3dNowMap     = 7,
}

#[derive(Debug,PartialEq)]
pub enum Modex86
{
    /// 16-bit mode (X86)
    Mode16 = 1 << 1, 
    /// 32-bit mode (X86)
    Mode32 = 1 << 2,
    /// 64-bit mode (X86)
    Mode64 = 1 << 3, 
}

// Structs
#[derive(Debug)]
pub struct Immediatex86{
    pub data: [i64; 2],
    pub kind: [u8; 2], // TODO: Remove if not used
    pub count: u8,
    pub offset: [u8; 2],
    pub translated: usize,
}

impl Default for Immediatex86 {
    fn default() -> Immediatex86 {
        Immediatex86 {
            data: [0,0],
            kind: [0,0],
            count: 0,
            offset: [0,0],
            translated: 0,
        }
    }
}

#[derive(Debug)]
pub struct Displacementx86{
    pub data: i32,
    pub offset: u8,
}

impl Default for Displacementx86 {
    fn default() -> Displacementx86 {
        Displacementx86 {
            data: 0,
            offset: 0,
        }
    }
}

#[derive(Debug)]
pub struct Registerx86
{
    pub data: u8,
    pub opcode_data: u8,
    pub id: u8,
    pub kind: u8,
    pub base: u8,
    pub mask: u8,
    pub vvvv: u8,
}

impl Default for Registerx86 {
    fn default() -> Registerx86 {
        Registerx86 {
            data: 0,
            opcode_data: 0,
            id: 0,
            kind: 0,
            base: 0,
            mask: 0,
            vvvv: 0,
        }
    }
}

#[derive(Debug)]
pub struct Opcodex86
{
    pub data: [u8; 4],
    /// The instruction ID, extracted from the decode table
    pub id: u16,
    /// The type of opcode, used for indexing into the array of decode tables
    pub kind: OpcodeTypex86,
    pub size: u8,
    pub escape_byte2: u8,
    pub escape_byte3: u8,
    pub mod_rm: bool,
}

impl Default for Opcodex86 {
    fn default() -> Opcodex86 {
        Opcodex86 {
            data: [0; 4],
            id: 0,
            kind: OpcodeTypex86::OneByte,
            size: 0,
            escape_byte2: 0,
            escape_byte3: 0,
            mod_rm: false,
        }
    }
}

/// Scaled-Index-Base byte (SIB) state structure.
#[derive(Debug)]
pub struct SibLayout
{
    pub data: u8,
    pub sib_index: u8,
    pub sib_scale: u8,
    pub sib_base: u8,
}

impl Default for SibLayout {
    fn default() -> SibLayout {
        SibLayout {
            data: 0,
            sib_index: 0,
            sib_scale: 0,
            sib_base: 0,
        }
    }
}
/// Contains the location (for use with the reader) of the prefix byte.
#[derive(Debug)]
pub struct PrefixStatex86
{
    
    pub prefix_flags: u32,
    /// track unused prefixes
    pub kind: [u8; 6], 
    /// Intel supports 6 types of prefixes, whereas AMD supports 5 types
    pub location: [u64; 6],
    /// xAcquireRelease
    pub x_acquire_release: bool, 
    pub vex_type: VexExType,
    pub vex_prefix: [u8; 4],
    pub segment: u8,
    pub offset: u64,
}

impl Default for PrefixStatex86 {
    fn default() -> PrefixStatex86 {
        PrefixStatex86 {
            prefix_flags: 0,
            kind: [0; 6],
            location: [0; 6], 
            x_acquire_release: false,
            vex_type: VexExType::NoXop,
            vex_prefix: [0; 4],
            segment: 0,
            offset: 0,
        }
    }
}

/// These fields determine the allowable values for the ModR/M fields, which
/// depend on operand and address widths
/// The Mod and R/M fields can encode a base for an effective address, or a
/// register.  These are separated into two fields here
#[derive(Debug)]
pub struct ModRmx86
{
    pub data: u16,
    /// referenced original RM
    pub ref_data: u16, 
    pub kind: RegType,
    pub base_reg: u16,
    pub base_ea_reg: u16,
    pub base_ea_base: u16,
    pub base_ea: u16,
    pub displacement_ea: EADisplacement,
    /// The displacement, used for memory operands
    pub displacement:Option<Displacementx86>,
    /// SIB state
    pub sib: Option<SibLayout>,
}

impl Default for ModRmx86 {
    fn default() -> ModRmx86 {
        ModRmx86 {
            data: 0,
            ref_data: 0, 
            kind: RegType::EABases,
            base_reg: 0,
            base_ea_reg: 0,
            base_ea_base: 0,
            base_ea: 0,
            displacement_ea: EADisplacement::Size0,
            displacement: None,
            sib: None,
        }
    }
}

/// The specification for how to extract and interpret one operand.
#[derive(Debug)]
pub struct OperandDisplay
{
    encoding: u8,
    kind: u8,
}

/// the internal assembled code container
#[derive(Debug, Copy, Clone)]
pub struct CodeInfo<'a>
{
    pub code: &'a[u8],
    pub size: usize, 
    pub offset: u64,
    pub address: u64,
}
#[derive(Debug)]
pub struct Sizesx86
{
    pub address: u8,
    pub register: u8,
    pub immediate: u8,
    pub displacement: u8,
    pub imm: u8
}

impl Default for Sizesx86 {
    fn default() -> Sizesx86 {
        Sizesx86 {
            address: 0,
            register: 0,
            immediate: 0,
            displacement: 0,
            imm: 0,
        }
    }
}

/// The internal instruction container
#[derive(Debug)]
pub struct Instructionx86<'a>
{
    pub cinfo: CodeInfo<'a>,
    /// The start of the instruction, usable with the reader
    pub start: u64,
    /// the current position in the reader
    pub cursor: u64,
    /// The last byte of the opcode, not counting any ModR/M extension
    pub end: u64,
    /// The length of the instruction, in bytes
    pub length: usize,
    pub size: Sizesx86,
    /// The mode to disassemble for (64-bit, protected, real)
    pub mode: Modex86,
    /// holds the state of the prefixes
    pub prefix: PrefixStatex86,
    /// opcode state
    pub opcode: Opcodex86,
    /// various critical pieces of data, in bytes
    pub register: Option<Registerx86>,
    /// Immediates.  There can be two in some cases
    pub immediates: Option<Immediatex86>,
    /// Portions of the ModR/M byte
    pub mod_rm: Option<ModRmx86>,
    /// The specification for how to extract and interpret one operand.
    pub display: Option<OperandDisplay>, 
    pub instr_index: u16,
    pub instr_spec: Option<u16>,
    pub operand_size: u16,
    pub operands: Option<[OperandSetPair; 6]>,
}
#[derive(Debug, Copy, Clone, Serialize, Deserialize, Default)]
pub struct InstrMemx86{
    pub segment: i32,
    pub base: i32,
    pub index: i32,
    pub scale: i32,
    pub displacement: i64,
    
}

impl InstrMemx86 {
    fn new() -> InstrMemx86 {
        InstrMemx86{
            segment: 0,
            base: 0,
            index: 0,
            scale: 0,
            displacement: 0,
        }
    }
}
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum InstrOpTypex86{
    Invalid=0,
    Reg=1,
    Imm=2,
    FpImm=3,
    Mem=4,
}

impl Default for InstrOpTypex86 {
    fn default() -> InstrOpTypex86 { InstrOpTypex86::Invalid }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, Default)]
pub struct InstrOperandsx86{
    pub op_type: InstrOpTypex86,
    pub reg: u8,
    pub imm: i64,
    pub fp: f64,
    pub mem: InstrMemx86,
    pub size: u8,
    pub avx_bcast: u8,
    pub avx_zero_opmask: bool,
    pub pc_relative_addr: bool,
}

impl InstrOperandsx86 {
    fn new() -> InstrOperandsx86 {
        InstrOperandsx86 {
            op_type: InstrOpTypex86::Invalid,
            reg: 0,
            imm: 0,
            fp: 0.0,
            mem: InstrMemx86::new(),
            size: 0,
            avx_bcast: 0,
            avx_zero_opmask: false,
            pc_relative_addr: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
/// Instruction Detail
pub struct X86Detail{
    pub prefix: [u8; 4],
    pub opcode: [u8; 4],
    pub printing_opcode: u32,
    pub rex: u8,
    pub address_size: u8,
    pub mod_rm: u8,
    pub sib: u8,
    pub sib_index: u16,
    pub sib_scale: u8,
    pub sib_base: u16,
    pub displacement: i32,
    // SSE Code Condition
    pub sse_cc: u8,
    // AVX Code Condition
    pub avx_cc: u8,
    // AVX Suppress all Exception
    pub avx_sae: bool,
    pub avx_rm: u8,
    pub op_count: usize,
    pub operands: [InstrOperandsx86; 8],
}

impl ArchDetail for X86Detail{
    fn prefix(&mut self) -> &mut [u8; 4] {
        &mut self.prefix
    }
    fn opcode(&mut self) -> &mut [u8; 4] {
        &mut self.opcode
    }
    fn printing_opcode(&mut self) -> &mut u32 {
        &mut self.printing_opcode
    }
    fn rex(&mut self) -> &mut u8 {
        &mut self.rex
    }
    fn address_size(&mut self) -> &mut u8 {
        &mut self.address_size
    }
    fn operands(&mut self) -> &mut [InstrOperandsx86; 8] {
        &mut self.operands
    }
    fn op_count(&mut self) -> &mut usize {
        &mut self.op_count
    }
    fn mod_rm(&mut self) -> &mut u8 {
        &mut self.mod_rm
    }
    fn sib(&mut self) -> &mut u8 {
        &mut self.sib
    }
    fn sib_index(&mut self) -> &mut u16 {
        &mut self.sib_index
    }
    fn sib_scale(&mut self) -> &mut u8 {
        &mut self.sib_scale
    }
    fn sib_base(&mut self) -> &mut u16 {
        &mut self.sib_base
    }
    fn displacement(&mut self) -> &mut i32 {
        &mut self.displacement
    }
    fn sse_cc(&mut self) -> &mut u8 {
        &mut self.sse_cc
    }
    fn avx_cc(&mut self) -> &mut u8 {
        &mut self.avx_cc
    }
    fn avx_sae(&mut self) -> &mut bool {
        &mut self.avx_sae
    }
    fn avx_rm(&mut self) -> &mut u8 {
        &mut self.avx_rm
    }
    fn new()->X86Detail{
        X86Detail{
            prefix: [0,0,0,0],
            opcode: [0,0,0,0],
            printing_opcode: 0,
            rex: 0,
            address_size: 0,
            mod_rm: 0,
            sib: 0,
            sib_index: 0,
            sib_scale: 0,
            sib_base: 0,
            displacement: 0,
            sse_cc: 0,
            avx_cc: 0,
            avx_sae: false,
            avx_rm: 0,
            op_count: 0,
            operands: [
                InstrOperandsx86::new(),
                InstrOperandsx86::new(),
                InstrOperandsx86::new(),
                InstrOperandsx86::new(),
                InstrOperandsx86::new(),
                InstrOperandsx86::new(),
                InstrOperandsx86::new(),
                InstrOperandsx86::new(),
            ]
        }
    }
    fn clone(&mut self)->X86Detail{
        X86Detail{
            prefix: self.prefix,
            opcode: self.opcode,
            printing_opcode: self.printing_opcode,
            rex: self.rex,
            address_size: self.address_size,
            mod_rm: self.mod_rm,
            sib: self.sib,
            sib_index: self.sib_index,
            sib_scale: self.sib_scale,
            sib_base: self.sib_base,
            displacement: self.displacement,
            sse_cc: self.sse_cc,
            avx_cc: self.avx_cc,
            avx_sae: self.avx_sae,
            avx_rm: self.avx_rm,
            op_count: self.op_count,
            operands: self.operands,
        }
    }
}

// Macro Rules
#[macro_export]
macro_rules! as_ref {
    ($o:ident, $i:ident, $j:ident) => (*($o.$i.as_ref().map(|v| &v.$j).unwrap()));
    ($o:ident, $i:ident, $j:ident, $k:ident) => (($o.$i.as_ref().map(|$i| &$i.$j).unwrap()).as_ref().map(|$j| &$j.$k).unwrap());
}

#[macro_export]
macro_rules! as_mut {
    ($o:ident, $i:ident, $j:ident, $e:expr) => (
        match $o.$i{
            Some( ref mut $i ) => {
                $i.$j = $e;
            }
            None=>{},
        }
    );
    ($o:ident, $i:ident, $j:ident, $k:ident, $e:expr) => 
    (
        match $o.$i{
            Some( ref mut $i ) => {
                match $i.$j{
                    Some( ref mut $j ) => {
                        $j.$k = $e;
                    }
                    None=>{},
                }
            },
            None => {}
        }
    );
}

#[macro_export]
/// Set the Mask for REX and VEX features.
macro_rules! accessor {
    // SIB
    (sib_scale: $e:expr) =>     ((($e) & 0xc0) >> 6);
    (sib_index: $e:expr) =>     ((($e) & 0x38) >> 3);
    (sib_base: $e:expr) =>      (($e) & 0x7);
    // MODRM 
    (mod: $e:expr) =>           ((($e) & 0xc0) >> 6);
    (reg: $e:expr) =>           ((($e) & 0x38) >> 3);
    (rm: $e:expr) =>            (($e) & 0x7);
    (rexb: $e:expr) =>          (($e) & 0x1);
    (rexx: $e:expr) =>          ((($e) & 0x2) >> 1);
    (rexr: $e:expr) =>          ((($e) & 0x4) >> 2);
    (rexw: $e:expr) =>          ((($e) & 0x8) >> 3);
    // EVex
    (EVexR2_2_4: $e:expr) =>    ((!($e) & 0x10) >> 4); /* 2 of 4 */
    (EVexB_2_4: $e:expr) =>     ((!($e) & 0x20) >> 5); /* 2 of 4 */
    (EVexX_2_4: $e:expr) =>     ((!($e) & 0x40) >> 6); /* 2 of 4 */
    (EVexR_2_4: $e:expr) =>     ((!($e) & 0x80) >> 7); /* 2 of 4 */
    (EVexW_3_4: $e:expr) =>     ((($e) & 0x80) >> 7); /* 3 of 4 */
    (EVexPP_3_4: $e:expr) =>    (($e) & 0x3); /* 3 of 4 */
    (EVexVVVV_3_4: $e:expr) =>  ((!($e) & 0x78) >> 3); /* 3 of 4 */
    (EVexMM_2_4: $e:expr) =>    (($e) & 0x3); 
    (EVexV2_4_4: $e:expr) =>    ((!($e) & 0x8) >> 3);
    (EVexZ_4_4: $e:expr) =>     ((($e) & 0x80) >> 7);
    (EVexB_4_4: $e:expr) =>     ((($e) & 0x10) >> 4);
    (EVexAAA_4_4: $e:expr) =>   (($e) & 0x7);
    (EVexL_4_4: $e:expr) =>     ((($e) & 0x20) >> 5);
    (EVexL2_4_4: $e:expr) =>    ((($e) & 0x40) >> 6);
    //Vex
    (VexR_2_2: $e:expr) =>      ((!($e) & 0x80) >> 7); /* 2 of 2 */
    (VexPP_2_2: $e:expr) =>     (($e) & 0x3); /* 2 of 2 */
    (VexVVVV_2_2: $e:expr) =>   ((!($e) & 0x78) >> 3); /* 2 of 2 */
    (VexW_3_3: $e:expr) =>      ((($e) & 0x80) >> 7); /* 3 of 3 */
    (VexR_2_3: $e:expr) =>      ((!($e) & 0x80) >> 7); /* 2 of 3  */
    (VexX_2_3: $e:expr) =>      ((!($e) & 0x40) >> 6); /* 2 of 3 */
    (VexB_2_3: $e:expr) =>      ((!($e) & 0x20) >> 5); /* 2 of 3 */
    (VexPP_3_3: $e:expr) =>     (($e) & 0x3); /* 3 of 3 */
    (VexVVVV_3_3: $e:expr) =>   ((!($e) & 0x78) >> 3); /* 3 of 3 */
    (VexMMMMM_2_3: $e:expr) =>  (($e) & 0x1f);
    (VexL_3_3: $e:expr) =>      ((($e) & 0x4) >> 2);
    (VexL_2_2: $e:expr) =>      ((($e) & 0x4) >> 2);
    //Xop
    (XopR_2_3: $e:expr) =>      ((!($e) & 0x80) >> 7); /* 2 of 3  */
    (XopX_2_3: $e:expr) =>      ((!($e) & 0x40) >> 6); /* 2 of 3 */
    (XopB_2_3: $e:expr) =>      ((!($e) & 0x20) >> 5); /* 2 of 3 */
    (XopW_3_3: $e:expr) =>      ((($e) & 0x80) >> 7); /* 3 of 3 */
    (XopPP_3_3: $e:expr) =>     (($e) & 0x3); /* 3 of 3 */
    (XopVVVV_3_3: $e:expr) =>   ((!($e) & 0x78) >> 3); /* 3 of 3 */
    (XopMMMMM_2_3: $e:expr) =>  (($e) & 0x1f);
    (XopL_3_3: $e:expr) =>      ((($e) & 0x4) >> 2);
}

// Generic functions
/// Set the next byte and increment the cursor.
pub fn get_byte(
    _instr: &mut Instructionx86, 
    _byte: &mut u8) -> bool
{
    disasm_debug!("get_byte()");
    if _instr.cinfo.offset < _instr.cinfo.address
    {
        return false;
    }
    let address_offset = (_instr.cinfo.offset-_instr.cinfo.address) as usize;
    // Check the code range
    let offset_size: usize = (_instr.cursor-_instr.cinfo.offset) as usize;
    if offset_size+address_offset >= _instr.cinfo.size{
        disasm_debug!("size not big enough()");
        return false;
    }
    
    let byte_index = (_instr.cursor-_instr.cinfo.offset) as usize;
    *_byte = _instr.cinfo.code[byte_index+address_offset];
    _instr.cursor=_instr.cursor+1;
    return true
}

/// Look at the next byte but don't increment the cursor.
pub fn peek_byte(
    _instr: &mut Instructionx86, 
    _byte: &mut u8) -> bool
{
    let address_offset = (_instr.cinfo.offset-_instr.cinfo.address) as usize;
    // Check the code range
    let offset_size: usize = (_instr.cursor-_instr.cinfo.offset) as usize;
    if offset_size+address_offset >= _instr.cinfo.size{
        return false;
    }
    let byte_index = (_instr.cursor-_instr.cinfo.offset) as usize;
    *_byte = _instr.cinfo.code[byte_index+address_offset];
    return true
}

/// Decrement the cursor.
pub fn release_byte(_instr: &mut Instructionx86){
    _instr.cursor=_instr.cursor-1;
}

pub fn get_int<T: Num + NumCast + Copy + 'static>(
    _instr: &mut Instructionx86) -> Option<T>
    where u64: AsPrimitive<T>
{
    let result = ::arch::x86::analyzex86::read_int::<T>(_instr.cursor as usize, _instr.cinfo.address as usize, &_instr.cinfo.code);
    if result.is_some() {
        _instr.cursor += ::std::mem::size_of::<T>() as u64;
    }
    return result;
}


impl <'a>Instructionx86<'a>{
    pub fn new(_code: CodeInfo<'a>)->Instructionx86<'a>{
        Instructionx86{
            cinfo: _code,
            start: _code.offset,
            cursor: _code.offset,
            end: 0,
            length: 0,
            size: Sizesx86{..Default::default()},
            mode: Modex86::Mode32,
            prefix: PrefixStatex86{..Default::default()},
            opcode: Opcodex86{..Default::default()},
            register: None,
            immediates: None,
            mod_rm: None,
            display: None,
            instr_index: 0,
            instr_spec: None,
            operand_size: 0,
            operands: None,
        }
    }
}


pub fn disasmx86<T: ArchDetail + Debug>(
    _code: &[u8], 
    _size: usize,
    _length: &mut usize,
    _address: u64, 
    _instructions: &mut Instruction<T>, 
    _mode: &Mode) -> bool
{ 
    let code_info = CodeInfo{
        code: _code,
        size: _size, 
        offset: _address,
        address: _instructions.address,
    };
    let mut instr = Instructionx86::new(code_info);
    let ret: bool = match _mode {
        _mode if *_mode as u8 == Modex86::Mode16 as u8 => decode_instructionx86(&mut instr, Modex86::Mode16),
        _mode if *_mode as u8 == Modex86::Mode32 as u8 => decode_instructionx86(&mut instr, Modex86::Mode32),
        _mode if *_mode as u8 == Modex86::Mode64 as u8 => decode_instructionx86(&mut instr, Modex86::Mode64),
        _ =>{
            error!("Mode is not valid. Please choose (Mode16, Mode32, Mode64)");
            false
        },
    };
    if !ret {
        *_length = (instr.cursor - _address) as usize;
        return false;
    }
    instr.end = instr.cursor;
    *_length = instr.length;
    if !build_instruction(&instr, _instructions){
        return false;
    }

    disasm_debug!("internal _instructions {:#?}", instr);
    disasm_debug!("_instructions {:?}", _instructions);
    return ret;
}

fn decode_instructionx86(
    _instr: &mut Instructionx86, 
    _mode: Modex86) -> bool 
{
    _instr.mode = _mode;
    if !prefix_read(_instr){ 
        disasm_debug!("prefix_read() failed");
        return false; 
    }
    if !opcode_read(_instr){ 
        disasm_debug!("opcode_read() failed");
        return false; 
    }
    if !instruction_index_read(_instr){ 
        disasm_debug!("instruction_index_read() failed");
        return false; 
    }
    if !check_illegal_prefix(_instr){
        disasm_debug!("check_illegal_prefix() failed");
        return false; 
    }
    if !operand_read(_instr){ 
        disasm_debug!("operand_read() failed");
        return false; 
    }
    _instr.length = (_instr.cursor - _instr.start) as usize;
    if _instr.length > 15 { 
        disasm_debug!("instruction length exceeded 15 bytes");
        return false; 
    }

    if _instr.operand_size == 0 {
        _instr.operand_size = _instr.size.address as u16;
    }
    let spec: usize =match _instr.instr_spec { Some(ref s)=>*s as usize, None=>0 };
    _instr.operands=Some(DISASMX86_OPERANDSETS[spec]);

    return true;
}