use arch::x86::archx86::*;
use std::fmt::Debug;

#[derive(Debug)]
pub enum Arch {
    ArchX86,
    ArchAll,
}

#[derive(Debug, Copy, Clone, PartialEq, Serialize)]
pub enum Mode {
    /// little-endian mode (default mode)
    ModeLittleEndian = 0,
    /// 16-bit mode (X86)
    Mode16 = 1 << 1,
    /// 32-bit mode (X86)
    Mode32 = 1 << 2,
    /// 64-bit mode (X86, PPC)
    Mode64 = 1 << 3,
    /// big-endian mode
    ModeBigEndian = 1 << 4,
}
impl Mode {
    pub fn get_size(&self) -> usize
    {
        return match *self
        {
            Mode::Mode16=>2,
            Mode::Mode32=>4,
            Mode::Mode64=>8,
            _=>4
        }
    }
}

pub trait ArchDetail{
    fn new() -> Self;
    // x86 details
    fn prefix(&mut self) -> &mut [u8; 4];
    fn opcode(&mut self) -> &mut [u8; 4];
    fn printing_opcode(&mut self) -> &mut u32;
    fn rex(&mut self) -> &mut u8;
    fn address_size(&mut self) -> &mut u8;
    fn operands(&mut self) -> &mut [InstrOperandsx86; 8];
    fn op_count(&mut self) -> &mut usize;
    fn mod_rm(&mut self) -> &mut u8;
    fn sib(&mut self) -> &mut u8;
    fn sib_index(&mut self) -> &mut u16;
    fn sib_scale(&mut self) -> &mut u8;
    fn sib_base(&mut self) -> &mut u16;
    fn displacement(&mut self) -> &mut i32;
    fn sse_cc(&mut self) -> &mut u8;
    fn avx_cc(&mut self) -> &mut u8;
    fn avx_sae(&mut self) -> &mut bool;
    fn avx_rm(&mut self) -> &mut u8;
    fn clone(&mut self)-> Self;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Instruction<T: ?Sized + ArchDetail + Debug> {
    pub opcode: u32,
    pub address: u64,
    pub offset: u64,
    pub size: usize,
    pub bytes: [u8; 16],
    pub mnemonic: String,
    pub op_str: String,
    #[serde(skip_deserializing, skip_serializing)]
    pub skipped_bytes: u8,
    #[serde(skip_deserializing, skip_serializing)] 
    pub detail: T,
}

impl Instruction<X86Detail>{
    pub fn new()->Instruction<X86Detail>{
        Instruction{
            opcode: 0,
            address: 0,
            offset: 0,
            size: 0,
            bytes: [0; 16],
            mnemonic: String::with_capacity(32),
            op_str: String::with_capacity(160),
            skipped_bytes: 0,
            detail: X86Detail::new(),
        }
    }
    pub fn clone(&mut self)->Instruction<X86Detail>{
        Instruction{
            opcode: self.opcode,
            address: self.address,
            offset: self.offset,
            size: self.size,
            bytes: self.bytes,
            mnemonic: self.mnemonic.clone(),
            op_str: self.op_str.clone(),
            skipped_bytes: self.skipped_bytes,
            detail: self.detail.clone(),
        }
    }
}

impl<T: ArchDetail + Debug> Debug for Instruction<T>{
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
            write!(f, "Instruction {{ mnemonic: {:?}, op_str: {:?},\n detail: {:#?} }}", self.mnemonic, self.op_str, self.detail)
        }
}

pub struct Xori {
    pub arch: Arch,
    pub mode: Mode,
}
 

impl Xori 
{
    /// Set up the architecture type for the disassembler type
    /// and prepares the returned instruction container.
    /// 
    /// # Example:
    ///
    /// ```rust,ignore
    /// let xi = Xori { arch: Arch::ArchX86, mode: Mode::Mode32 };
    /// let binary32 = b"\xe9\x1e\x00\x00\x00\xb8\x04\
    /// \x00\x00\x00\xbb\x01\x00\x00\x00\x59\xba\x0f\
    /// \x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\
    /// \x00\x00\x00\x00\xcd\x80\xe8\xdd\xff\xff\xff\
    /// \x48\x65\x6c\x6c\x6f\x2c\x20\x57\x6f\x72\x6c\
    /// \x64\x21\x0d\x0a";
    /// let mut vec: Vec<Instruction<X86Detail>> = Vec::new();
    /// let start_address = 0x1000;
    /// xi.disasm(binary32, binary32.len(), start_address, start_address, 0, &mut vec);
    /// if vec.len() > 0
    /// {
    ///     for instr in vec.iter_mut()
    ///     {
    ///         let addr: String = format!("0x{:x}", instr.address);
    ///         println!("{:16}{} {}", addr, instr.mnemonic, instr.op_str);
    ///     }
    /// }
    /// ```   
    pub fn disasm(
        &self, 
        _code: &[u8], 
        _size: usize, 
        _address: usize,
        _offset: usize,
        _chunk: usize, // optional
        _instr: &mut Vec<Instruction<X86Detail>>) -> bool 
    {
        // TODO Figure out generic vector
        let mut _next_offset: usize = 0;

        let mut end = _address + _size;
        if _chunk != 0{
            if _offset + _chunk <= _address + _size{
                end = _offset + _chunk;
            }
        }
        let mut offset = _offset as u64;
        let mut ret: bool;
        match self.arch
        {
            Arch::ArchX86 => {
                let mut length: usize = 0;
                while (offset as usize) < end {
                    // initalize vector;
                    let mut instructions: Instruction<X86Detail>;
                    instructions = Instruction::new();
                    instructions.address = _address as u64;
                    instructions.offset = offset;
                    ret = if let Some(x86_mode) = Modex86::from_mode(&self.mode) {
                        disasmx86(_code, _size, &mut length, offset as u64, &mut instructions, x86_mode)
                    } else {
                        false
                    };
                    if ret {
                        _next_offset = length;
                        length = 0;
                    } else {
                        if offset as usize > _address as usize{
                            instructions.address = offset as u64;
                            let byte_offset = offset as usize - _address as usize;
                            if byte_offset < _code.len(){
                                instructions.bytes = [_code[byte_offset],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
                                instructions.mnemonic = String::from("db");
                                instructions.op_str = format!("0x{:x}", _code[byte_offset]);
                                instructions.size = 1;
                            }
                        }
                        instructions.skipped_bytes=1;
                        _next_offset = 1;
                    }
                    _instr.push(instructions);
                    offset += _next_offset as u64;
                }
            },
            _=>{},
            // TODO: Mulitple Arches
        }
            
        if _instr.len() > 0{
            return true;
        }
        return false;
    }
}

