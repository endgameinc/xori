//cpux86.rs
#[allow(dead_code)]
use std::fmt::Debug;
use arch::x86::registersx86::*;

#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub struct SegmentState{
    pub fs: i64, // The TEB of the current thread can be accessed from FS segment
    pub gs: i64,
    pub es: i64,
    pub ds: i64,
    pub cs: i64,
    pub ss: i64,
}

impl SegmentState {
    fn new()-> SegmentState {
        SegmentState{
            fs: 0, //F Segment, Pointer to still more extra data
            gs: 0, //G Segment, Pointer to more extra data
            es: 0, //Extra Segment
            ds: 0, //Data Segment
            cs: 0, //Code Segment
            ss: 0, //Stack Segment
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegContents{
    pub value: i64,
    pub detail: String,
}

impl RegContents {
    fn new()-> RegContents {
        RegContents{
            value: 0,
            detail: String::with_capacity(256),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RegisterState{
    pub eax: RegContents,
    pub ebp: RegContents,
    pub ebx: RegContents,
    pub ecx: RegContents,
    pub edi: RegContents,
    pub edx: RegContents,
    pub eip: RegContents,
    pub esi: RegContents,
    pub esp: RegContents,
    pub r8: RegContents,
    pub r9: RegContents,
    pub r10: RegContents,
    pub r11: RegContents,
    pub r12: RegContents,
    pub r13: RegContents,
    pub r14: RegContents,
    pub r15: RegContents,
}

impl RegisterState {
    fn new()-> RegisterState {
        RegisterState{
            eax: RegContents::new(),
            ebp: RegContents::new(),
            ebx: RegContents::new(),
            ecx: RegContents::new(),
            edi: RegContents::new(),
            edx: RegContents::new(),
            eip: RegContents::new(),
            esi: RegContents::new(),
            esp: RegContents::new(),
            r8: RegContents::new(),
            r9: RegContents::new(),
            r10: RegContents::new(),
            r11: RegContents::new(),
            r12: RegContents::new(),
            r13: RegContents::new(),
            r14: RegContents::new(),
            r15: RegContents::new(),
        }
    }
}
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub struct BoundRegisterState{
    bnd0: i64,
    bnd1: i64,
    bnd2: i64,
    bnd3: i64,
}

impl BoundRegisterState {
    fn new()-> BoundRegisterState {
        BoundRegisterState{
            bnd0: 0,
            bnd1: 0,
            bnd2: 0,
            bnd3: 0,
        }
    }
}
#[derive(Debug, Copy, Clone)]
pub struct Floatx80{
    low: u64,
    high: u16,
}

impl Floatx80 {
    fn new()-> Floatx80 {
        Floatx80{
            low: 0,
            high: 0,
        }
    }
}
#[derive(Debug, Copy, Clone)]
pub struct FPRegister{
    float: Floatx80,
    mmx: MMXRegister,
}

impl FPRegister {
    fn new()-> FPRegister {
        FPRegister{
            float: Floatx80::new(),
            mmx: MMXRegister::new(),
        }
    }
}
#[derive(Debug, Copy, Clone)]
pub struct XMMRegister {
    _b: [u8; 16],
    _w: [u16; 8],
    _l: [u32; 4],
    _q: [u64; 2],
    _s: [f32; 4],
    _d: [f64; 2],
} 

impl XMMRegister {
    fn new()-> XMMRegister {
        XMMRegister{
            _b: [0; 16],
            _w: [0; 8],
            _l: [0; 4],
            _q: [0; 2],
            _s: [0.0; 4],
            _d: [0.0; 2],
        }
    }
}
#[derive(Debug, Copy, Clone)]
pub struct YMMRegister {
    _b: [u8; 32],
    _w: [u16; 16],
    _l: [u32; 8],
    _q: [u64; 4],
    _s: [f32; 8],
    _d: [f64; 4],
}

impl YMMRegister {
    fn new()-> YMMRegister {
        YMMRegister{
            _b: [0; 32],
            _w: [0; 16],
            _l: [0; 8],
            _q: [0; 4],
            _s: [0.0; 8],
            _d: [0.0; 4],
        }
    }
}
#[derive(Copy, Clone)]
pub struct ZMMRegister {
    _b: [u8; 64],
    _w: [u16; 32],
    _l: [u32; 16],
    _q: [u64; 8],
    _s: [f32; 16],
    _d: [f64; 8],
} 

impl Debug for ZMMRegister{
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
            write!(f, "ZMMRegister {{ }}")
        }
}

impl ZMMRegister {
    fn new()-> ZMMRegister {
        ZMMRegister{
            _b: [0; 64],
            _w: [0; 32],
            _l: [0; 16],
            _q: [0; 8],
            _s: [0.0; 16],
            _d: [0.0; 8],
        }
    }
}
#[derive(Debug, Copy, Clone)]
pub struct MMXRegister {
    _b: [u8; 8],
    _w: [u16; 4],
    _l: [u32; 2],
    _s: [f32; 2],
    _q: u64,
}

impl MMXRegister {
    fn new()-> MMXRegister {
        MMXRegister{
            _b: [0; 8],
            _w: [0; 4],
            _l: [0; 2],
            _s: [0.0; 2],
            _q: 0,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Flags {
    _cf: u8, //Carry flag
    _pf: u8, //Parity flag
    _af: u8, //Auxiliary carry flag
    _zf: u8, //Zero flag
    _sf: u8, //Sign flag
    _tf: u8, //Trace flag
    _if: u8, //Interrupt flag
    _df: u8, //Direction flag
    _of: u8, //Overflow flag
}

impl Flags {
    fn new()-> Flags {
        Flags{
           _cf: 0, //Carry flag
           _pf: 0, //Parity flag
           _af: 0, //Auxiliary carry flag
           _zf: 0, //Zero flag
           _sf: 0, //Sign flag
           _tf: 0, //Trace flag
           _if: 0, //Interrupt flag
           _df: 0, //Direction flag
           _of: 0, //Overflow flag
        }
    }
}

#[derive(Debug,Clone,PartialEq)]
pub enum EFlags{
    Invalid,
    Carry,
    Parity,
    Auxiliary,
    Zero,
    Sign,
    Trace,
    Interrupt,
    Direction,
    Overflow,
}

#[derive(Debug,Clone,Copy,PartialEq)]
pub enum FlagDefined
{
    Undefined,
    Set,
    Unset,
}

#[derive(Debug, Clone)]
pub struct CPUStatex86 {
    pub address_size: u8,
    pub regs: RegisterState,
    pub segments: SegmentState,
    pub stack_address: u64,
    pub eflags: Flags,
    pub bound_regs: BoundRegisterState,
    pub fp_regs: [FPRegister; 8],
    pub mmx_regs: [MMXRegister; 16],
    pub xmm_regs: [XMMRegister; 16],
    pub ymm_regs: [YMMRegister; 16],
    pub zmm_regs: [ZMMRegister; 16],
}

impl CPUStatex86 {
    pub fn new()-> CPUStatex86 {
        CPUStatex86{
            address_size: 4,
            regs: RegisterState::new(),
            segments: SegmentState::new(),
            stack_address: 0,
            eflags: Flags::new(),
            bound_regs: BoundRegisterState::new(),
            fp_regs: [FPRegister::new(); 8],
            mmx_regs: [MMXRegister::new(); 16],
            xmm_regs: [XMMRegister::new(); 16],
            ymm_regs: [YMMRegister::new(); 16],
            zmm_regs: [ZMMRegister::new(); 16],
        }
    }
    pub fn set_register(
        &mut self,
        _reg: &u8, 
        value: i64)
    {
        //debug!("get_register()");
        match *_reg {
            r if r == Registersx86::AL as u8=>{
                //debug!("set al 0x{:x}", ((self.regs.eax.value >> 8) << 8) | (value & 0xFF));
                self.regs.eax.value = ((self.regs.eax.value >> 8) << 8) | (value & 0xFF)
            },
            r if r == Registersx86::AH as u8=>{
                self.regs.eax.value = (((self.regs.eax.value >> 16) << 16) | (self.regs.eax.value & 0xFF)) | ((value & 0xFF) << 8)
            },
            r if r == Registersx86::AX as u8=> self.regs.eax.value = ((self.regs.eax.value >> 16) << 16) | (value & 0xFFFF),
            r if r == Registersx86::EAX as u8=> {
                //debug!("set eax 0x{:x}", ((self.regs.eax.value >> 32) << 32) | (value & 0xFFFFFFFF));
                self.regs.eax.value = ((self.regs.eax.value >> 32) << 32) | (value & 0xFFFFFFFF)
            },
            r if r == Registersx86::RAX as u8=> self.regs.eax.value ={
                //debug!("set rax 0x{:x}", value);
                value
            },
            r if r == Registersx86::BL as u8=> self.regs.ebx.value = ((self.regs.ebx.value  >> 8) << 8) | (value & 0xFF),
            r if r == Registersx86::BH as u8=> {
                self.regs.ebx.value = (((self.regs.ebx.value >> 16) << 16) | (self.regs.ebx.value & 0xFF)) | ((value & 0xFF) << 8)
            },
            r if r == Registersx86::BX as u8=> self.regs.ebx.value = ((self.regs.ebx.value >> 16) << 16) | (value & 0xFFFF),
            r if r == Registersx86::EBX as u8=> self.regs.ebx.value = ((self.regs.ebx.value >> 32) << 32) | (value & 0xFFFFFFFF),
            r if r == Registersx86::RBX as u8=> self.regs.ebx.value = value,
            r if r == Registersx86::CL as u8=> self.regs.ecx.value = ((self.regs.ecx.value  >> 8) << 8) | (value & 0xFF),
            r if r == Registersx86::CH as u8=> {
                self.regs.ecx.value = (((self.regs.ecx.value >> 16) << 16) | (self.regs.ecx.value & 0xFF)) | ((value & 0xFF) << 8)
            },
            r if r == Registersx86::CX as u8=> self.regs.ecx.value = ((self.regs.ecx.value  >> 16) << 16) | (value & 0xFFFF),
            r if r == Registersx86::ECX as u8=>{
                self.regs.ecx.value=((self.regs.edx.value >> 32) << 32) | (value & 0xFFFFFFFF);
            }
            r if r == Registersx86::RCX as u8=> self.regs.ecx.value = value,
            r if r == Registersx86::DL as u8=> self.regs.edx.value = ((self.regs.edx.value  >> 8) << 8) | (value & 0xFF),
            r if r == Registersx86::DH as u8=> {
                self.regs.edx.value = (((self.regs.edx.value >> 16) << 16) | (self.regs.edx.value & 0xFF)) | ((value & 0xFF) << 8)
            }, 
            r if r == Registersx86::DX as u8=> self.regs.edx.value = ((self.regs.edx.value  >> 16) << 16) | (value & 0xFFFF),
            r if r == Registersx86::EDX as u8=> self.regs.edx.value= ((self.regs.edx.value >> 32) << 32) | (value & 0xFFFFFFFF),
            r if r == Registersx86::RDX as u8=> self.regs.edx.value = value,
            r if r == Registersx86::BP as u8=> self.regs.ebp.value = ((self.regs.ebp.value  >> 16) << 16) | (value & 0xFFFF),
            r if r == Registersx86::EBP as u8=> self.regs.ebp.value= ((self.regs.ebp.value >> 32) << 32) | (value & 0xFFFFFFFF),
            r if r == Registersx86::RBP as u8=> self.regs.ebp.value = value,
            r if r == Registersx86::DI as u8=> self.regs.edi.value = ((self.regs.edi.value  >> 16) << 16) | (value & 0xFFFF),
            r if r == Registersx86::EDI as u8=> self.regs.edi.value= ((self.regs.edi.value >> 32) << 32) | (value & 0xFFFFFFFF),
            r if r == Registersx86::RDI as u8=> self.regs.edi.value = value,
            r if r == Registersx86::SI as u8=> self.regs.esi.value = ((self.regs.esi.value  >> 16) << 16) | (value & 0xFFFF),
            r if r == Registersx86::ESI as u8=> self.regs.esi.value= ((self.regs.esi.value >> 32) << 32) | (value & 0xFFFFFFFF),
            r if r == Registersx86::RSI as u8=> self.regs.esi.value = value,
            r if r == Registersx86::SP as u8=> self.regs.esp.value = ((self.regs.esp.value  >> 16) << 16) | (value & 0xFFFF),
            r if r == Registersx86::ESP as u8=> self.regs.esp.value= ((self.regs.esp.value >> 32) << 32) | (value & 0xFFFFFFFF),
            r if r == Registersx86::RSP as u8=> self.regs.esp.value = value,
            r if r == Registersx86::EIP as u8=> self.regs.eip.value= ((self.regs.esp.value >> 32) << 32) | (value & 0xFFFFFFFF),
            r if r == Registersx86::RIP as u8=> self.regs.eip.value = value,
            r if r == Registersx86::SS as u8=>{
                self.segments.ss = value;
            },
            r if r == Registersx86::DS as u8=>{
                self.segments.ds = value;
            },
            r if r == Registersx86::CS as u8=>{
                self.segments.cs = value;
            },
            r if r == Registersx86::ES as u8=>{
                self.segments.es = value;
            },
            r if r == Registersx86::FS as u8=>{
                self.segments.fs = value;
            },
            r if r == Registersx86::GS as u8=>{
                self.segments.gs = value;
            },
            _=>{},
        }
    }

    pub fn get_register(
        &mut self,
        _reg: &u8,
        _instr_size: usize,
        )->i64
    {
        //debug!("get_register()");
        match *_reg {
            r if r == Registersx86::AL as u8=>return self.regs.eax.value & 0xFF,
            r if r == Registersx86::AH as u8=>return (self.regs.eax.value >> 8) & 0xFF,
            r if r == Registersx86::AX as u8=>return self.regs.eax.value & 0xFFFF,
            r if r == Registersx86::EAX as u8=>{
                //debug!("get eax 0x{:x}", self.regs.eax.value & 0xFFFFFFFF);
                return self.regs.eax.value & 0xFFFFFFFF;
            },
            r if r == Registersx86::RAX as u8=>{
                //debug!("get rax 0x{:x}", self.regs.eax.value);
                return self.regs.eax.value;
            },
            r if r == Registersx86::BL as u8=>return self.regs.ebx.value & 0xFF,
            r if r == Registersx86::BH as u8=>return (self.regs.ebx.value >> 8) & 0xFF,
            r if r == Registersx86::BX as u8=>return self.regs.ebx.value & 0xFFFF,
            r if r == Registersx86::EBX as u8=>return self.regs.ebx.value & 0xFFFFFFFF,
            r if r == Registersx86::RBX as u8=>return self.regs.ebx.value,
            r if r == Registersx86::CL as u8=>return self.regs.ecx.value & 0xFF,
            r if r == Registersx86::CH as u8=>return (self.regs.ecx.value >> 8) & 0xFF,
            r if r == Registersx86::CX as u8=>return self.regs.ecx.value & 0xFFFF,
            r if r == Registersx86::ECX as u8=>{
                //debug!("ecx 0x{:x}", self.regs.ecx.value & 0xFFFFFFFF);
                return self.regs.ecx.value & 0xFFFFFFFF;
            },
            r if r == Registersx86::RCX as u8=>{

                return self.regs.ecx.value;
            },
            r if r == Registersx86::DL as u8=>return self.regs.edx.value & 0xFF,
            r if r == Registersx86::DH as u8=>return (self.regs.edx.value >> 8) & 0xFF,
            r if r == Registersx86::DX as u8=>return self.regs.edx.value & 0xFFFF,
            r if r == Registersx86::EDX as u8=>return self.regs.edx.value & 0xFFFFFFFF,
            r if r == Registersx86::RDX as u8=>return self.regs.edx.value,
            r if r == Registersx86::BP as u8=>return self.regs.ebp.value & 0xFFFF,
            r if r == Registersx86::EBP as u8=>return self.regs.ebp.value & 0xFFFFFFFF,
            r if r == Registersx86::RBP as u8=>return self.regs.ebp.value,
            r if r == Registersx86::DI as u8=>return self.regs.edi.value & 0xFFFF,
            r if r == Registersx86::EDI as u8=>return self.regs.edi.value & 0xFFFFFFFF,
            r if r == Registersx86::RDI as u8=>return self.regs.edi.value,
            r if r == Registersx86::SI as u8=>return self.regs.esi.value & 0xFFFF,
            r if r == Registersx86::ESI as u8=>return self.regs.esi.value & 0xFFFFFFFF,
            r if r == Registersx86::RSI as u8=>return self.regs.esi.value,
            r if r == Registersx86::SP as u8=>return self.regs.esp.value & 0xFFFF,
            r if r == Registersx86::ESP as u8=>return self.regs.esp.value & 0xFFFFFFFF,
            r if r == Registersx86::RSP as u8=>return self.regs.esp.value,
            r if r == Registersx86::EIP as u8=>{
                return (self.regs.eip.value & 0xFFFFFFFF) + _instr_size as i64
            },
            r if r == Registersx86::RIP as u8=>{
                //debug!("Registersx86::RIP");
                return self.regs.eip.value + _instr_size as i64;
            },
            r if r == Registersx86::SS as u8=>{
                return self.segments.ss;
            },
            r if r == Registersx86::DS as u8=>{
                return self.segments.ds;
            },
            r if r == Registersx86::CS as u8=>{
                return self.segments.cs;
            },
            r if r == Registersx86::ES as u8=>{
                return self.segments.es;
            },
            r if r == Registersx86::FS as u8=>{
                return self.segments.fs;
            },
            r if r == Registersx86::GS as u8=>{
                return self.segments.gs;
            },
            _=>return 0,
        }
    }
    
    pub fn get_flag(
        &mut self,
        _flag: &EFlags)->u8
    {
        match *_flag{
            EFlags::Invalid=>0,
            EFlags::Carry=>self.eflags._cf,
            EFlags::Parity=>self.eflags._pf,
            EFlags::Auxiliary=>self.eflags._af,
            EFlags::Zero=>self.eflags._zf,
            EFlags::Sign=>self.eflags._sf,
            EFlags::Trace=>self.eflags._cf,
            EFlags::Interrupt=>self.eflags._if,
            EFlags::Direction=>self.eflags._df,
            EFlags::Overflow=>self.eflags._of,
        }

    }
    
    pub fn set_flag(
        &mut self,
        _flag: &EFlags, 
        value: u8)
    {
        match *_flag{
            EFlags::Invalid=>{},
            EFlags::Carry=>self.eflags._cf = value,
            EFlags::Parity=>self.eflags._pf = value,
            EFlags::Auxiliary=>self.eflags._af = value,
            EFlags::Zero=>self.eflags._zf = value,
            EFlags::Sign=>self.eflags._sf = value,
            EFlags::Trace=>self.eflags._cf = value,
            EFlags::Interrupt=>self.eflags._if = value,
            EFlags::Direction=>self.eflags._df = value,
            EFlags::Overflow=>self.eflags._of = value,
        }
    }
}


