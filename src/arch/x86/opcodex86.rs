// opcodex86.rs

use arch::x86::archx86::*;
use arch::x86::prefixx86::*;
use arch::x86::registersx86::*;

/// Values for the VEX m-mmmm leading opcode bytes
pub enum VexXopOpcode {
  /// 0x0F leading opcode byte.
  /// Encoded in two bytes.
  Vex0F = 0x1,
  /// 0x0F 0x38 leading opcode bytes.
  Vex0F38 = 0x2,
  /// 0x0F 0x3A leading opcode bytes.
  Vex0F3A = 0x3,
  /// Only XOP instructions.
  Xop8 = 0x8,
  /// Only XOP and TBM instructions.
  Xop9 = 0x9,
  /// TBM instructions.
  XopA = 0xA,
}

/// Effective Address Displacement Sizes
pub enum EADisplacement{
  Size0,
  Size8,
  Size16,
  Size32,
}

#[derive(Debug,PartialEq)]
pub enum RegType{
    EABases,
    AllRegisters,
}

/// Effective Address Bases
#[repr(u8)]
#[derive(Debug)]
#[allow(dead_code)]
pub enum EABases{
    NoBase,
    BXSI,
    BXDI,
    BPSI,
    BPDI,
    SI,
    DI,
    BP,
    BX,
    R8W,
    R9W,
    R10W,
    R11W,
    R12W,
    R13W,
    R14W,
    R15W,
    EAX,
    ECX,
    EDX,
    EBX,
    Sib,
    EBP,
    ESI,
    EDI,
    R8D,
    R9D,
    R10D,
    R11D,
    R12D,
    R13D,
    R14D,
    R15D,
    RAX,
    RCX,
    RDX,
    RBX,
    Sib64,
    RBP,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Max,
}

#[repr(u8)]
#[derive(Debug)]
#[allow(dead_code)]
pub enum SibIndexes{
    NoBase,
    BXSI,
    BXDI,
    BPSI,
    BPDI,
    SI,
    DI,
    BP,
    BX,
    R8W,
    R9W,
    R10W,
    R11W,
    R12W,
    R13W,
    R14W,
    R15W,
    EAX,
    ECX,
    EDX,
    EBX,
    Sib,
    EBP,
    ESI,
    EDI,
    R8D,
    R9D,
    R10D,
    R11D,
    R12D,
    R13D,
    R14D,
    R15D,
    RAX,
    RCX,
    RDX,
    RBX,
    Sib64,
    RBP,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    XMM0,
    XMM1,
    XMM2,
    XMM3,
    XMM4,
    XMM5,
    XMM6,
    XMM7,
    XMM8,
    XMM9,
    XMM10,
    XMM11,
    XMM12,
    XMM13,
    XMM14,
    XMM15,
    XMM16,
    XMM17,
    XMM18,
    XMM19,
    XMM20,
    XMM21,
    XMM22,
    XMM23,
    XMM24,
    XMM25,
    XMM26,
    XMM27,
    XMM28,
    XMM29,
    XMM30,
    XMM31,
    YMM0,
    YMM1,
    YMM2,
    YMM3,
    YMM4,
    YMM5,
    YMM6,
    YMM7,
    YMM8,
    YMM9,
    YMM10,
    YMM11,
    YMM12,
    YMM13,
    YMM14,
    YMM15,
    YMM16,
    YMM17,
    YMM18,
    YMM19,
    YMM20,
    YMM21,
    YMM22,
    YMM23,
    YMM24,
    YMM25,
    YMM26,
    YMM27,
    YMM28,
    YMM29,
    YMM30,
    YMM31,
    ZMM0,
    ZMM1,
    ZMM2,
    ZMM3,
    ZMM4,
    ZMM5,
    ZMM6,
    ZMM7,
    ZMM8,
    ZMM9,
    ZMM10,
    ZMM11,
    ZMM12,
    ZMM13,
    ZMM14,
    ZMM15,
    ZMM16,
    ZMM17,
    ZMM18,
    ZMM19,
    ZMM20,
    ZMM21,
    ZMM22,
    ZMM23,
    ZMM24,
    ZMM25,
    ZMM26,
    ZMM27,
    ZMM28,
    ZMM29,
    ZMM30,
    ZMM31,
    Max,
}

pub enum AllRegisters{
    NoReg,
    AL,
    CL,
    DL,
    BL,
    AH,
    CH,
    DH,
    BH,
    R8B,
    R9B,
    R10B,
    R11B,
    R12B,
    R13B,
    R14B,
    R15B,
    SPL,
    BPL,
    SIL,
    DIL,
    AX,
    CX,
    DX,
    BX,
    SP,
    BP,
    SI,
    DI,
    R8W,
    R9W,
    R10W,
    R11W,
    R12W,
    R13W,
    R14W,
    R15W,
    EAX,
    ECX,
    EDX,
    EBX,
    ESP,
    EBP,
    ESI,
    EDI,
    R8D,
    R9D,
    R10D,
    R11D,
    R12D,
    R13D,
    R14D,
    R15D,
    RAX,
    RCX,
    RDX,
    RBX,
    RSP,
    RBP,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    MM0,
    MM1,
    MM2,
    MM3,
    MM4,
    MM5,
    MM6,
    MM7,
    XMM0,
    XMM1,
    XMM2,
    XMM3,
    XMM4,
    XMM5,
    XMM6,
    XMM7,
    XMM8,
    XMM9,
    XMM10,
    XMM11,
    XMM12,
    XMM13,
    XMM14,
    XMM15,
    XMM16,
    XMM17,
    XMM18,
    XMM19,
    XMM20,
    XMM21,
    XMM22,
    XMM23,
    XMM24,
    XMM25,
    XMM26,
    XMM27,
    XMM28,
    XMM29,
    XMM30,
    XMM31,
    YMM0,
    YMM1,
    YMM2,
    YMM3,
    YMM4,
    YMM5,
    YMM6,
    YMM7,
    YMM8,
    YMM9,
    YMM10,
    YMM11,
    YMM12,
    YMM13,
    YMM14,
    YMM15,
    YMM16,
    YMM17,
    YMM18,
    YMM19,
    YMM20,
    YMM21,
    YMM22,
    YMM23,
    YMM24,
    YMM25,
    YMM26,
    YMM27,
    YMM28,
    YMM29,
    YMM30,
    YMM31,
    ZMM0,
    ZMM1,
    ZMM2,
    ZMM3,
    ZMM4,
    ZMM5,
    ZMM6,
    ZMM7,
    ZMM8,
    ZMM9,
    ZMM10,
    ZMM11,
    ZMM12,
    ZMM13,
    ZMM14,
    ZMM15,
    ZMM16,
    ZMM17,
    ZMM18,
    ZMM19,
    ZMM20,
    ZMM21,
    ZMM22,
    ZMM23,
    ZMM24,
    ZMM25,
    ZMM26,
    ZMM27,
    ZMM28,
    ZMM29,
    ZMM30,
    ZMM31,
    K0,
    K1,
    K2,
    K3,
    K4,
    K5,
    K6,
    K7,
    ES,
    CS,
    SS,
    DS,
    FS,
    GS,
    DR0,
    DR1,
    DR2,
    DR3,
    DR4,
    DR5,
    DR6,
    DR7,
    CR0,
    CR1,
    CR2,
    CR3,
    CR4,
    CR5,
    CR6,
    CR7,
    CR8,
    CR9,
    CR10,
    CR11,
    CR12,
    CR13,
    CR14,
    CR15,
    RIP,
    Max,
}

impl AllRegisters {
    pub fn translate(_index: u8) -> u8{
        return match _index{
            i if i == AllRegisters::AL as u8=>Registersx86::AL as u8,
            i if i == AllRegisters::CL as u8=>Registersx86::CL as u8,
            i if i == AllRegisters::DL as u8=>Registersx86::DL as u8,
            i if i == AllRegisters::BL as u8=>Registersx86::BL as u8,
            i if i == AllRegisters::AH as u8=>Registersx86::AH as u8,
            i if i == AllRegisters::CH as u8=>Registersx86::CH as u8,
            i if i == AllRegisters::DH as u8=>Registersx86::DH as u8,
            i if i == AllRegisters::BH as u8=>Registersx86::BH as u8,
            i if i == AllRegisters::R8B as u8=>Registersx86::R8B as u8,
            i if i == AllRegisters::R9B as u8=>Registersx86::R9B as u8,
            i if i == AllRegisters::R10B as u8=>Registersx86::R10B as u8,
            i if i == AllRegisters::R11B as u8=>Registersx86::R11B as u8,
            i if i == AllRegisters::R12B as u8=>Registersx86::R12B as u8,
            i if i == AllRegisters::R13B as u8=>Registersx86::R13B as u8,
            i if i == AllRegisters::R14B as u8=>Registersx86::R14B as u8,
            i if i == AllRegisters::R15B as u8=>Registersx86::R15B as u8,
            i if i == AllRegisters::SPL as u8=>Registersx86::SPL as u8,
            i if i == AllRegisters::BPL as u8=>Registersx86::BPL as u8,
            i if i == AllRegisters::SIL as u8=>Registersx86::SIL as u8,
            i if i == AllRegisters::DIL as u8=>Registersx86::DIL as u8,
            i if i == AllRegisters::AX as u8=>Registersx86::AX as u8,
            i if i == AllRegisters::CX as u8=>Registersx86::CX as u8,
            i if i == AllRegisters::DX as u8=>Registersx86::DX as u8,
            i if i == AllRegisters::BX as u8=>Registersx86::BX as u8,
            i if i == AllRegisters::SP as u8=>Registersx86::SP as u8,
            i if i == AllRegisters::BP as u8=>Registersx86::BP as u8,
            i if i == AllRegisters::SI as u8=>Registersx86::SI as u8,
            i if i == AllRegisters::DI as u8=>Registersx86::DI as u8,
            i if i == AllRegisters::R8W as u8=>Registersx86::R8W as u8,
            i if i == AllRegisters::R9W as u8=>Registersx86::R9W as u8,
            i if i == AllRegisters::R10W as u8=>Registersx86::R10W as u8,
            i if i == AllRegisters::R11W as u8=>Registersx86::R11W as u8,
            i if i == AllRegisters::R12W as u8=>Registersx86::R12W as u8,
            i if i == AllRegisters::R13W as u8=>Registersx86::R13W as u8,
            i if i == AllRegisters::R14W as u8=>Registersx86::R14W as u8,
            i if i == AllRegisters::R15W as u8=>Registersx86::R15W as u8,
            i if i == AllRegisters::EAX as u8=>Registersx86::EAX as u8,
            i if i == AllRegisters::ECX as u8=>Registersx86::ECX as u8,
            i if i == AllRegisters::EDX as u8=>Registersx86::EDX as u8,
            i if i == AllRegisters::EBX as u8=>Registersx86::EBX as u8,
            i if i == AllRegisters::ESP as u8=>Registersx86::ESP as u8,
            i if i == AllRegisters::EBP as u8=>Registersx86::EBP as u8,
            i if i == AllRegisters::ESI as u8=>Registersx86::ESI as u8,
            i if i == AllRegisters::EDI as u8=>Registersx86::EDI as u8,
            i if i == AllRegisters::R8D as u8=>Registersx86::R8D as u8,
            i if i == AllRegisters::R9D as u8=>Registersx86::R9D as u8,
            i if i == AllRegisters::R10D as u8=>Registersx86::R10D as u8,
            i if i == AllRegisters::R11D as u8=>Registersx86::R11D as u8,
            i if i == AllRegisters::R12D as u8=>Registersx86::R12D as u8,
            i if i == AllRegisters::R13D as u8=>Registersx86::R13D as u8,
            i if i == AllRegisters::R14D as u8=>Registersx86::R14D as u8,
            i if i == AllRegisters::R15D as u8=>Registersx86::R15D as u8,
            i if i == AllRegisters::RAX as u8=>Registersx86::RAX as u8,
            i if i == AllRegisters::RCX as u8=>Registersx86::RCX as u8,
            i if i == AllRegisters::RDX as u8=>Registersx86::RDX as u8,
            i if i == AllRegisters::RBX as u8=>Registersx86::RBX as u8,
            i if i == AllRegisters::RSP as u8=>Registersx86::RSP as u8,
            i if i == AllRegisters::RBP as u8=>Registersx86::RBP as u8,
            i if i == AllRegisters::RSI as u8=>Registersx86::RSI as u8,
            i if i == AllRegisters::RDI as u8=>Registersx86::RDI as u8,
            i if i == AllRegisters::R8 as u8=>Registersx86::R8 as u8,
            i if i == AllRegisters::R9 as u8=>Registersx86::R9 as u8,
            i if i == AllRegisters::R10 as u8=>Registersx86::R10 as u8,
            i if i == AllRegisters::R11 as u8=>Registersx86::R11 as u8,
            i if i == AllRegisters::R12 as u8=>Registersx86::R12 as u8,
            i if i == AllRegisters::R13 as u8=>Registersx86::R13 as u8,
            i if i == AllRegisters::R14 as u8=>Registersx86::R14 as u8,
            i if i == AllRegisters::R15 as u8=>Registersx86::R15 as u8,
            i if i == AllRegisters::MM0 as u8=>Registersx86::MM0 as u8,
            i if i == AllRegisters::MM1 as u8=>Registersx86::MM1 as u8,
            i if i == AllRegisters::MM2 as u8=>Registersx86::MM2 as u8,
            i if i == AllRegisters::MM3 as u8=>Registersx86::MM3 as u8,
            i if i == AllRegisters::MM4 as u8=>Registersx86::MM4 as u8,
            i if i == AllRegisters::MM5 as u8=>Registersx86::MM5 as u8,
            i if i == AllRegisters::MM6 as u8=>Registersx86::MM6 as u8,
            i if i == AllRegisters::MM7 as u8=>Registersx86::MM7 as u8,
            i if i == AllRegisters::XMM0 as u8=>Registersx86::XMM0 as u8,
            i if i == AllRegisters::XMM1 as u8=>Registersx86::XMM1 as u8,
            i if i == AllRegisters::XMM2 as u8=>Registersx86::XMM2 as u8,
            i if i == AllRegisters::XMM3 as u8=>Registersx86::XMM3 as u8,
            i if i == AllRegisters::XMM4 as u8=>Registersx86::XMM4 as u8,
            i if i == AllRegisters::XMM5 as u8=>Registersx86::XMM5 as u8,
            i if i == AllRegisters::XMM6 as u8=>Registersx86::XMM6 as u8,
            i if i == AllRegisters::XMM7 as u8=>Registersx86::XMM7 as u8,
            i if i == AllRegisters::XMM8 as u8=>Registersx86::XMM8 as u8,
            i if i == AllRegisters::XMM9 as u8=>Registersx86::XMM9 as u8,
            i if i == AllRegisters::XMM10 as u8=>Registersx86::XMM10 as u8,
            i if i == AllRegisters::XMM11 as u8=>Registersx86::XMM11 as u8,
            i if i == AllRegisters::XMM12 as u8=>Registersx86::XMM12 as u8,
            i if i == AllRegisters::XMM13 as u8=>Registersx86::XMM13 as u8,
            i if i == AllRegisters::XMM14 as u8=>Registersx86::XMM14 as u8,
            i if i == AllRegisters::XMM15 as u8=>Registersx86::XMM15 as u8,
            i if i == AllRegisters::XMM16 as u8=>Registersx86::XMM16 as u8,
            i if i == AllRegisters::XMM17 as u8=>Registersx86::XMM17 as u8,
            i if i == AllRegisters::XMM18 as u8=>Registersx86::XMM18 as u8,
            i if i == AllRegisters::XMM19 as u8=>Registersx86::XMM19 as u8,
            i if i == AllRegisters::XMM20 as u8=>Registersx86::XMM20 as u8,
            i if i == AllRegisters::XMM21 as u8=>Registersx86::XMM21 as u8,
            i if i == AllRegisters::XMM22 as u8=>Registersx86::XMM22 as u8,
            i if i == AllRegisters::XMM23 as u8=>Registersx86::XMM23 as u8,
            i if i == AllRegisters::XMM24 as u8=>Registersx86::XMM24 as u8,
            i if i == AllRegisters::XMM25 as u8=>Registersx86::XMM25 as u8,
            i if i == AllRegisters::XMM26 as u8=>Registersx86::XMM26 as u8,
            i if i == AllRegisters::XMM27 as u8=>Registersx86::XMM27 as u8,
            i if i == AllRegisters::XMM28 as u8=>Registersx86::XMM28 as u8,
            i if i == AllRegisters::XMM29 as u8=>Registersx86::XMM29 as u8,
            i if i == AllRegisters::XMM30 as u8=>Registersx86::XMM30 as u8,
            i if i == AllRegisters::XMM31 as u8=>Registersx86::XMM31 as u8,
            i if i == AllRegisters::YMM0 as u8=>Registersx86::YMM0 as u8,
            i if i == AllRegisters::YMM1 as u8=>Registersx86::YMM1 as u8,
            i if i == AllRegisters::YMM2 as u8=>Registersx86::YMM2 as u8,
            i if i == AllRegisters::YMM3 as u8=>Registersx86::YMM3 as u8,
            i if i == AllRegisters::YMM4 as u8=>Registersx86::YMM4 as u8,
            i if i == AllRegisters::YMM5 as u8=>Registersx86::YMM5 as u8,
            i if i == AllRegisters::YMM6 as u8=>Registersx86::YMM6 as u8,
            i if i == AllRegisters::YMM7 as u8=>Registersx86::YMM7 as u8,
            i if i == AllRegisters::YMM8 as u8=>Registersx86::YMM8 as u8,
            i if i == AllRegisters::YMM9 as u8=>Registersx86::YMM9 as u8,
            i if i == AllRegisters::YMM10 as u8=>Registersx86::YMM10 as u8,
            i if i == AllRegisters::YMM11 as u8=>Registersx86::YMM11 as u8,
            i if i == AllRegisters::YMM12 as u8=>Registersx86::YMM12 as u8,
            i if i == AllRegisters::YMM13 as u8=>Registersx86::YMM13 as u8,
            i if i == AllRegisters::YMM14 as u8=>Registersx86::YMM14 as u8,
            i if i == AllRegisters::YMM15 as u8=>Registersx86::YMM15 as u8,
            i if i == AllRegisters::YMM16 as u8=>Registersx86::YMM16 as u8,
            i if i == AllRegisters::YMM17 as u8=>Registersx86::YMM17 as u8,
            i if i == AllRegisters::YMM18 as u8=>Registersx86::YMM18 as u8,
            i if i == AllRegisters::YMM19 as u8=>Registersx86::YMM19 as u8,
            i if i == AllRegisters::YMM20 as u8=>Registersx86::YMM20 as u8,
            i if i == AllRegisters::YMM21 as u8=>Registersx86::YMM21 as u8,
            i if i == AllRegisters::YMM22 as u8=>Registersx86::YMM22 as u8,
            i if i == AllRegisters::YMM23 as u8=>Registersx86::YMM23 as u8,
            i if i == AllRegisters::YMM24 as u8=>Registersx86::YMM24 as u8,
            i if i == AllRegisters::YMM25 as u8=>Registersx86::YMM25 as u8,
            i if i == AllRegisters::YMM26 as u8=>Registersx86::YMM26 as u8,
            i if i == AllRegisters::YMM27 as u8=>Registersx86::YMM27 as u8,
            i if i == AllRegisters::YMM28 as u8=>Registersx86::YMM28 as u8,
            i if i == AllRegisters::YMM29 as u8=>Registersx86::YMM29 as u8,
            i if i == AllRegisters::YMM30 as u8=>Registersx86::YMM30 as u8,
            i if i == AllRegisters::YMM31 as u8=>Registersx86::YMM31 as u8,
            i if i == AllRegisters::ZMM0 as u8=>Registersx86::ZMM0 as u8,
            i if i == AllRegisters::ZMM1 as u8=>Registersx86::ZMM1 as u8,
            i if i == AllRegisters::ZMM2 as u8=>Registersx86::ZMM2 as u8,
            i if i == AllRegisters::ZMM3 as u8=>Registersx86::ZMM3 as u8,
            i if i == AllRegisters::ZMM4 as u8=>Registersx86::ZMM4 as u8,
            i if i == AllRegisters::ZMM5 as u8=>Registersx86::ZMM5 as u8,
            i if i == AllRegisters::ZMM6 as u8=>Registersx86::ZMM6 as u8,
            i if i == AllRegisters::ZMM7 as u8=>Registersx86::ZMM7 as u8,
            i if i == AllRegisters::ZMM8 as u8=>Registersx86::ZMM8 as u8,
            i if i == AllRegisters::ZMM9 as u8=>Registersx86::ZMM9 as u8,
            i if i == AllRegisters::ZMM10 as u8=>Registersx86::ZMM10 as u8,
            i if i == AllRegisters::ZMM11 as u8=>Registersx86::ZMM11 as u8,
            i if i == AllRegisters::ZMM12 as u8=>Registersx86::ZMM12 as u8,
            i if i == AllRegisters::ZMM13 as u8=>Registersx86::ZMM13 as u8,
            i if i == AllRegisters::ZMM14 as u8=>Registersx86::ZMM14 as u8,
            i if i == AllRegisters::ZMM15 as u8=>Registersx86::ZMM15 as u8,
            i if i == AllRegisters::ZMM16 as u8=>Registersx86::ZMM16 as u8,
            i if i == AllRegisters::ZMM17 as u8=>Registersx86::ZMM17 as u8,
            i if i == AllRegisters::ZMM18 as u8=>Registersx86::ZMM18 as u8,
            i if i == AllRegisters::ZMM19 as u8=>Registersx86::ZMM19 as u8,
            i if i == AllRegisters::ZMM20 as u8=>Registersx86::ZMM20 as u8,
            i if i == AllRegisters::ZMM21 as u8=>Registersx86::ZMM21 as u8,
            i if i == AllRegisters::ZMM22 as u8=>Registersx86::ZMM22 as u8,
            i if i == AllRegisters::ZMM23 as u8=>Registersx86::ZMM23 as u8,
            i if i == AllRegisters::ZMM24 as u8=>Registersx86::ZMM24 as u8,
            i if i == AllRegisters::ZMM25 as u8=>Registersx86::ZMM25 as u8,
            i if i == AllRegisters::ZMM26 as u8=>Registersx86::ZMM26 as u8,
            i if i == AllRegisters::ZMM27 as u8=>Registersx86::ZMM27 as u8,
            i if i == AllRegisters::ZMM28 as u8=>Registersx86::ZMM28 as u8,
            i if i == AllRegisters::ZMM29 as u8=>Registersx86::ZMM29 as u8,
            i if i == AllRegisters::ZMM30 as u8=>Registersx86::ZMM30 as u8,
            i if i == AllRegisters::ZMM31 as u8=>Registersx86::ZMM31 as u8,
            i if i == AllRegisters::K0 as u8=>Registersx86::K0 as u8,
            i if i == AllRegisters::K1 as u8=>Registersx86::K1 as u8,
            i if i == AllRegisters::K2 as u8=>Registersx86::K2 as u8,
            i if i == AllRegisters::K3 as u8=>Registersx86::K3 as u8,
            i if i == AllRegisters::K4 as u8=>Registersx86::K4 as u8,
            i if i == AllRegisters::K5 as u8=>Registersx86::K5 as u8,
            i if i == AllRegisters::K6 as u8=>Registersx86::K6 as u8,
            i if i == AllRegisters::K7 as u8=>Registersx86::K7 as u8,
            i if i == AllRegisters::ES as u8=>Registersx86::ES as u8,
            i if i == AllRegisters::CS as u8=>Registersx86::CS as u8,
            i if i == AllRegisters::SS as u8=>Registersx86::SS as u8,
            i if i == AllRegisters::DS as u8=>Registersx86::DS as u8,
            i if i == AllRegisters::FS as u8=>Registersx86::FS as u8,
            i if i == AllRegisters::GS as u8=>Registersx86::GS as u8,
            i if i == AllRegisters::DR0 as u8=>Registersx86::DR0 as u8,
            i if i == AllRegisters::DR1 as u8=>Registersx86::DR1 as u8,
            i if i == AllRegisters::DR2 as u8=>Registersx86::DR2 as u8,
            i if i == AllRegisters::DR3 as u8=>Registersx86::DR3 as u8,
            i if i == AllRegisters::DR4 as u8=>Registersx86::DR4 as u8,
            i if i == AllRegisters::DR5 as u8=>Registersx86::DR5 as u8,
            i if i == AllRegisters::DR6 as u8=>Registersx86::DR6 as u8,
            i if i == AllRegisters::DR7 as u8=>Registersx86::DR7 as u8,
            i if i == AllRegisters::CR0 as u8=>Registersx86::CR0 as u8,
            i if i == AllRegisters::CR1 as u8=>Registersx86::CR1 as u8,
            i if i == AllRegisters::CR2 as u8=>Registersx86::CR2 as u8,
            i if i == AllRegisters::CR3 as u8=>Registersx86::CR3 as u8,
            i if i == AllRegisters::CR4 as u8=>Registersx86::CR4 as u8,
            i if i == AllRegisters::CR5 as u8=>Registersx86::CR5 as u8,
            i if i == AllRegisters::CR6 as u8=>Registersx86::CR6 as u8,
            i if i == AllRegisters::CR7 as u8=>Registersx86::CR7 as u8,
            i if i == AllRegisters::CR8 as u8=>Registersx86::CR8 as u8,
            i if i == AllRegisters::CR9 as u8=>Registersx86::CR9 as u8,
            i if i == AllRegisters::CR10 as u8=>Registersx86::CR10 as u8,
            i if i == AllRegisters::CR11 as u8=>Registersx86::CR11 as u8,
            i if i == AllRegisters::CR12 as u8=>Registersx86::CR12 as u8,
            i if i == AllRegisters::CR13 as u8=>Registersx86::CR13 as u8,
            i if i == AllRegisters::CR14 as u8=>Registersx86::CR14 as u8,
            i if i == AllRegisters::CR15 as u8=>Registersx86::CR15 as u8,
            i if i == AllRegisters::RIP as u8=>Registersx86::RIP as u8,
            _=>0,
        }
    }
}

impl EABases{
    pub fn translate(_index: u8) -> u8{
        return match _index{
            i if i == EABases::BXSI as u8=>Registersx86::BX as u8,
            i if i == EABases::BXDI as u8=>Registersx86::BX as u8,
            i if i == EABases::BPSI as u8=>Registersx86::BP as u8,
            i if i == EABases::BPDI as u8=>Registersx86::BP as u8,
            i if i == EABases::SI as u8=>Registersx86::SI as u8,
            i if i == EABases::DI as u8=>Registersx86::DI as u8,
            i if i == EABases::BP as u8=>Registersx86::BP as u8,
            i if i == EABases::BX as u8=>Registersx86::BX as u8,
            i if i == EABases::R8W as u8=>Registersx86::R8W as u8,
            i if i == EABases::R9W as u8=>Registersx86::R9W as u8,
            i if i == EABases::R10W as u8=>Registersx86::R10W as u8,
            i if i == EABases::R11W as u8=>Registersx86::R11W as u8,
            i if i == EABases::R12W as u8=>Registersx86::R12W as u8,
            i if i == EABases::R13W as u8=>Registersx86::R13W as u8,
            i if i == EABases::R14W as u8=>Registersx86::R14W as u8,
            i if i == EABases::R15W as u8=>Registersx86::R15W as u8,
            i if i == EABases::EAX as u8=>Registersx86::EAX as u8,
            i if i == EABases::ECX as u8=>Registersx86::ECX as u8,
            i if i == EABases::EDX as u8=>Registersx86::EDX as u8,
            i if i == EABases::EBX as u8=>Registersx86::EBX as u8,
            i if i == EABases::EBP as u8=>Registersx86::EBP as u8,
            i if i == EABases::ESI as u8=>Registersx86::ESI as u8,
            i if i == EABases::EDI as u8=>Registersx86::EDI as u8,
            i if i == EABases::R8D as u8=>Registersx86::R8D as u8,
            i if i == EABases::R9D as u8=>Registersx86::R9D as u8,
            i if i == EABases::R10D as u8=>Registersx86::R10D as u8,
            i if i == EABases::R11D as u8=>Registersx86::R11D as u8,
            i if i == EABases::R12D as u8=>Registersx86::R12D as u8,
            i if i == EABases::R13D as u8=>Registersx86::R13D as u8,
            i if i == EABases::R14D as u8=>Registersx86::R14D as u8,
            i if i == EABases::R15D as u8=>Registersx86::R15D as u8,
            i if i == EABases::RAX as u8=>Registersx86::RAX as u8,
            i if i == EABases::RCX as u8=>Registersx86::RCX as u8,
            i if i == EABases::RDX as u8=>Registersx86::RDX as u8,
            i if i == EABases::RBX as u8=>Registersx86::RBX as u8,
            i if i == EABases::RBP as u8=>Registersx86::RBP as u8,
            i if i == EABases::RSI as u8=>Registersx86::RSI as u8,
            i if i == EABases::RDI as u8=>Registersx86::RDI as u8,
            i if i == EABases::R8 as u8=>Registersx86::R8 as u8,
            i if i == EABases::R9 as u8=>Registersx86::R9 as u8,
            i if i == EABases::R10 as u8=>Registersx86::R10 as u8,
            i if i == EABases::R11 as u8=>Registersx86::R11 as u8,
            i if i == EABases::R12 as u8=>Registersx86::R12 as u8,
            i if i == EABases::R13 as u8=>Registersx86::R13 as u8,
            i if i == EABases::R14 as u8=>Registersx86::R14 as u8,
            i if i == EABases::R15 as u8=>Registersx86::R15 as u8,
            _=>0,
        }
    }
}

impl SibIndexes{
    pub fn translate(_index: u8) -> u8{
        return match _index{
            i if i == SibIndexes::BXSI as u8=>Registersx86::BX as u8,
            i if i == SibIndexes::BXDI as u8=>Registersx86::BX as u8,
            i if i == SibIndexes::BPSI as u8=>Registersx86::BP as u8,
            i if i == SibIndexes::BPDI as u8=>Registersx86::BP as u8,
            i if i == SibIndexes::SI as u8=>Registersx86::SI as u8,
            i if i == SibIndexes::DI as u8=>Registersx86::DI as u8,
            i if i == SibIndexes::BP as u8=>Registersx86::BP as u8,
            i if i == SibIndexes::BX as u8=>Registersx86::BX as u8,
            i if i == SibIndexes::R8W as u8=>Registersx86::R8W as u8,
            i if i == SibIndexes::R9W as u8=>Registersx86::R9W as u8,
            i if i == SibIndexes::R10W as u8=>Registersx86::R10W as u8,
            i if i == SibIndexes::R11W as u8=>Registersx86::R11W as u8,
            i if i == SibIndexes::R12W as u8=>Registersx86::R12W as u8,
            i if i == SibIndexes::R13W as u8=>Registersx86::R13W as u8,
            i if i == SibIndexes::R14W as u8=>Registersx86::R14W as u8,
            i if i == SibIndexes::R15W as u8=>Registersx86::R15W as u8,
            i if i == SibIndexes::EAX as u8=>Registersx86::EAX as u8,
            i if i == SibIndexes::ECX as u8=>Registersx86::ECX as u8,
            i if i == SibIndexes::EDX as u8=>Registersx86::EDX as u8,
            i if i == SibIndexes::EBX as u8=>Registersx86::EBX as u8,
            i if i == SibIndexes::EBP as u8=>Registersx86::EBP as u8,
            i if i == SibIndexes::ESI as u8=>Registersx86::ESI as u8,
            i if i == SibIndexes::EDI as u8=>Registersx86::EDI as u8,
            i if i == SibIndexes::R8D as u8=>Registersx86::R8D as u8,
            i if i == SibIndexes::R9D as u8=>Registersx86::R9D as u8,
            i if i == SibIndexes::R10D as u8=>Registersx86::R10D as u8,
            i if i == SibIndexes::R11D as u8=>Registersx86::R11D as u8,
            i if i == SibIndexes::R12D as u8=>Registersx86::R12D as u8,
            i if i == SibIndexes::R13D as u8=>Registersx86::R13D as u8,
            i if i == SibIndexes::R14D as u8=>Registersx86::R14D as u8,
            i if i == SibIndexes::R15D as u8=>Registersx86::R15D as u8,
            i if i == SibIndexes::RAX as u8=>Registersx86::RAX as u8,
            i if i == SibIndexes::RCX as u8=>Registersx86::RCX as u8,
            i if i == SibIndexes::RDX as u8=>Registersx86::RDX as u8,
            i if i == SibIndexes::RBX as u8=>Registersx86::RBX as u8,
            i if i == SibIndexes::RBP as u8=>Registersx86::RBP as u8,
            i if i == SibIndexes::RSI as u8=>Registersx86::RSI as u8,
            i if i == SibIndexes::RDI as u8=>Registersx86::RDI as u8,
            i if i == SibIndexes::R8 as u8=>Registersx86::R8 as u8,
            i if i == SibIndexes::R9 as u8=>Registersx86::R9 as u8,
            i if i == SibIndexes::R10 as u8=>Registersx86::R10 as u8,
            i if i == SibIndexes::R11 as u8=>Registersx86::R11 as u8,
            i if i == SibIndexes::R12 as u8=>Registersx86::R12 as u8,
            i if i == SibIndexes::R13 as u8=>Registersx86::R13 as u8,
            i if i == SibIndexes::R14 as u8=>Registersx86::R14 as u8,
            i if i == SibIndexes::R15 as u8=>Registersx86::R15 as u8,
            i if i == SibIndexes::XMM0 as u8=>Registersx86::XMM0 as u8,
            i if i == SibIndexes::XMM1 as u8=>Registersx86::XMM1 as u8,
            i if i == SibIndexes::XMM2 as u8=>Registersx86::XMM2 as u8,
            i if i == SibIndexes::XMM3 as u8=>Registersx86::XMM3 as u8,
            i if i == SibIndexes::XMM4 as u8=>Registersx86::XMM4 as u8,
            i if i == SibIndexes::XMM5 as u8=>Registersx86::XMM5 as u8,
            i if i == SibIndexes::XMM6 as u8=>Registersx86::XMM6 as u8,
            i if i == SibIndexes::XMM7 as u8=>Registersx86::XMM7 as u8,
            i if i == SibIndexes::XMM8 as u8=>Registersx86::XMM8 as u8,
            i if i == SibIndexes::XMM9 as u8=>Registersx86::XMM9 as u8,
            i if i == SibIndexes::XMM10 as u8=>Registersx86::XMM10 as u8,
            i if i == SibIndexes::XMM11 as u8=>Registersx86::XMM11 as u8,
            i if i == SibIndexes::XMM12 as u8=>Registersx86::XMM12 as u8,
            i if i == SibIndexes::XMM13 as u8=>Registersx86::XMM13 as u8,
            i if i == SibIndexes::XMM14 as u8=>Registersx86::XMM14 as u8,
            i if i == SibIndexes::XMM15 as u8=>Registersx86::XMM15 as u8,
            i if i == SibIndexes::XMM16 as u8=>Registersx86::XMM16 as u8,
            i if i == SibIndexes::XMM17 as u8=>Registersx86::XMM17 as u8,
            i if i == SibIndexes::XMM18 as u8=>Registersx86::XMM18 as u8,
            i if i == SibIndexes::XMM19 as u8=>Registersx86::XMM19 as u8,
            i if i == SibIndexes::XMM20 as u8=>Registersx86::XMM20 as u8,
            i if i == SibIndexes::XMM21 as u8=>Registersx86::XMM21 as u8,
            i if i == SibIndexes::XMM22 as u8=>Registersx86::XMM22 as u8,
            i if i == SibIndexes::XMM23 as u8=>Registersx86::XMM23 as u8,
            i if i == SibIndexes::XMM24 as u8=>Registersx86::XMM24 as u8,
            i if i == SibIndexes::XMM25 as u8=>Registersx86::XMM25 as u8,
            i if i == SibIndexes::XMM26 as u8=>Registersx86::XMM26 as u8,
            i if i == SibIndexes::XMM27 as u8=>Registersx86::XMM27 as u8,
            i if i == SibIndexes::XMM28 as u8=>Registersx86::XMM28 as u8,
            i if i == SibIndexes::XMM29 as u8=>Registersx86::XMM29 as u8,
            i if i == SibIndexes::XMM30 as u8=>Registersx86::XMM30 as u8,
            i if i == SibIndexes::XMM31 as u8=>Registersx86::XMM31 as u8,
            i if i == SibIndexes::YMM0 as u8=>Registersx86::YMM0 as u8,
            i if i == SibIndexes::YMM1 as u8=>Registersx86::YMM1 as u8,
            i if i == SibIndexes::YMM2 as u8=>Registersx86::YMM2 as u8,
            i if i == SibIndexes::YMM3 as u8=>Registersx86::YMM3 as u8,
            i if i == SibIndexes::YMM4 as u8=>Registersx86::YMM4 as u8,
            i if i == SibIndexes::YMM5 as u8=>Registersx86::YMM5 as u8,
            i if i == SibIndexes::YMM6 as u8=>Registersx86::YMM6 as u8,
            i if i == SibIndexes::YMM7 as u8=>Registersx86::YMM7 as u8,
            i if i == SibIndexes::YMM8 as u8=>Registersx86::YMM8 as u8,
            i if i == SibIndexes::YMM9 as u8=>Registersx86::YMM9 as u8,
            i if i == SibIndexes::YMM10 as u8=>Registersx86::YMM10 as u8,
            i if i == SibIndexes::YMM11 as u8=>Registersx86::YMM11 as u8,
            i if i == SibIndexes::YMM12 as u8=>Registersx86::YMM12 as u8,
            i if i == SibIndexes::YMM13 as u8=>Registersx86::YMM13 as u8,
            i if i == SibIndexes::YMM14 as u8=>Registersx86::YMM14 as u8,
            i if i == SibIndexes::YMM15 as u8=>Registersx86::YMM15 as u8,
            i if i == SibIndexes::YMM16 as u8=>Registersx86::YMM16 as u8,
            i if i == SibIndexes::YMM17 as u8=>Registersx86::YMM17 as u8,
            i if i == SibIndexes::YMM18 as u8=>Registersx86::YMM18 as u8,
            i if i == SibIndexes::YMM19 as u8=>Registersx86::YMM19 as u8,
            i if i == SibIndexes::YMM20 as u8=>Registersx86::YMM20 as u8,
            i if i == SibIndexes::YMM21 as u8=>Registersx86::YMM21 as u8,
            i if i == SibIndexes::YMM22 as u8=>Registersx86::YMM22 as u8,
            i if i == SibIndexes::YMM23 as u8=>Registersx86::YMM23 as u8,
            i if i == SibIndexes::YMM24 as u8=>Registersx86::YMM24 as u8,
            i if i == SibIndexes::YMM25 as u8=>Registersx86::YMM25 as u8,
            i if i == SibIndexes::YMM26 as u8=>Registersx86::YMM26 as u8,
            i if i == SibIndexes::YMM27 as u8=>Registersx86::YMM27 as u8,
            i if i == SibIndexes::YMM28 as u8=>Registersx86::YMM28 as u8,
            i if i == SibIndexes::YMM29 as u8=>Registersx86::YMM29 as u8,
            i if i == SibIndexes::YMM30 as u8=>Registersx86::YMM30 as u8,
            i if i == SibIndexes::YMM31 as u8=>Registersx86::YMM31 as u8,
            i if i == SibIndexes::ZMM0 as u8=>Registersx86::ZMM0 as u8,
            i if i == SibIndexes::ZMM1 as u8=>Registersx86::ZMM1 as u8,
            i if i == SibIndexes::ZMM2 as u8=>Registersx86::ZMM2 as u8,
            i if i == SibIndexes::ZMM3 as u8=>Registersx86::ZMM3 as u8,
            i if i == SibIndexes::ZMM4 as u8=>Registersx86::ZMM4 as u8,
            i if i == SibIndexes::ZMM5 as u8=>Registersx86::ZMM5 as u8,
            i if i == SibIndexes::ZMM6 as u8=>Registersx86::ZMM6 as u8,
            i if i == SibIndexes::ZMM7 as u8=>Registersx86::ZMM7 as u8,
            i if i == SibIndexes::ZMM8 as u8=>Registersx86::ZMM8 as u8,
            i if i == SibIndexes::ZMM9 as u8=>Registersx86::ZMM9 as u8,
            i if i == SibIndexes::ZMM10 as u8=>Registersx86::ZMM10 as u8,
            i if i == SibIndexes::ZMM11 as u8=>Registersx86::ZMM11 as u8,
            i if i == SibIndexes::ZMM12 as u8=>Registersx86::ZMM12 as u8,
            i if i == SibIndexes::ZMM13 as u8=>Registersx86::ZMM13 as u8,
            i if i == SibIndexes::ZMM14 as u8=>Registersx86::ZMM14 as u8,
            i if i == SibIndexes::ZMM15 as u8=>Registersx86::ZMM15 as u8,
            i if i == SibIndexes::ZMM16 as u8=>Registersx86::ZMM16 as u8,
            i if i == SibIndexes::ZMM17 as u8=>Registersx86::ZMM17 as u8,
            i if i == SibIndexes::ZMM18 as u8=>Registersx86::ZMM18 as u8,
            i if i == SibIndexes::ZMM19 as u8=>Registersx86::ZMM19 as u8,
            i if i == SibIndexes::ZMM20 as u8=>Registersx86::ZMM20 as u8,
            i if i == SibIndexes::ZMM21 as u8=>Registersx86::ZMM21 as u8,
            i if i == SibIndexes::ZMM22 as u8=>Registersx86::ZMM22 as u8,
            i if i == SibIndexes::ZMM23 as u8=>Registersx86::ZMM23 as u8,
            i if i == SibIndexes::ZMM24 as u8=>Registersx86::ZMM24 as u8,
            i if i == SibIndexes::ZMM25 as u8=>Registersx86::ZMM25 as u8,
            i if i == SibIndexes::ZMM26 as u8=>Registersx86::ZMM26 as u8,
            i if i == SibIndexes::ZMM27 as u8=>Registersx86::ZMM27 as u8,
            i if i == SibIndexes::ZMM28 as u8=>Registersx86::ZMM28 as u8,
            i if i == SibIndexes::ZMM29 as u8=>Registersx86::ZMM29 as u8,
            i if i == SibIndexes::ZMM30 as u8=>Registersx86::ZMM30 as u8,
            i if i == SibIndexes::ZMM31 as u8=>Registersx86::ZMM31 as u8,
            _=>0,
        }
    }
}

/// Set the opcode byte(s)
fn opcode_set(
    _instr: &mut Instructionx86, 
    _kind: OpcodeTypex86, 
    _byte2: u8, 
    _byte3: u8) -> bool
{
    disasm_debug!("opcode_set()");
    let mut byte: u8 = 0;
    if !get_byte(_instr, &mut byte){ return false;}
    _instr.opcode.kind = _kind;
    _instr.opcode.escape_byte2 = _byte2;
    _instr.opcode.escape_byte3 = _byte3;
    _instr.opcode.data[0] = byte;
    _instr.opcode.size = 1;
    return true;
}

fn init_sib(_instr: &mut Instructionx86)
{
    disasm_debug!("init_sib()");
    match _instr.mod_rm{
        Some( ref mut rm ) => {
            if rm.sib.is_none() 
            {
                rm.sib = Some(SibLayout{..Default::default()});
            }
        },
        None => {}
    }
}

fn init_displacement(_instr: &mut Instructionx86)
{
    disasm_debug!("init_displacement()");
    match _instr.mod_rm{
        Some( ref mut rm ) => {
            if rm.displacement.is_none() 
            {
                rm.displacement = Some(Displacementx86{ ..Default::default()});
            }
        },
        None => {}
    }
}

fn init_mod_rm(_instr: &mut Instructionx86)
{
    disasm_debug!("init_mod_rm()");
    if _instr.mod_rm.is_none(){
        _instr.mod_rm = Some(ModRmx86{..Default::default()});
    }
}

//determine addressing info for instruction by the scaled-index-base
fn opcode_read_sib(_instr: &mut Instructionx86) -> bool
{
    disasm_debug!("opcode_read_sib()");
    let mut _byte: u8 = 0;
    let mut _index: u8 = 0;
    let mut _base: u8 = 0;
    let mut sib_index: u8 = 0; 
    let mut sib_base: u8 = 0;

    // check if already enabled if not set to true
    if as_ref!(_instr, mod_rm, sib).is_some()
    { 
        return true;
    }
    init_sib(_instr);

    // check the address size
    match _instr.size.address
    { 
        2=>{
            return false;
        },
        4=>{
            sib_index = SibIndexes::EAX as u8;
            sib_base = AllRegisters::EAX as u8;
        },
        8=>{
            sib_index = SibIndexes::RAX as u8;
            sib_base = AllRegisters::RAX as u8;
        },
        _=>{},
    }

    // allocate the sib byte
    if !get_byte(_instr, &mut _byte){ return false; }
    as_mut!(_instr, mod_rm, sib, data, _byte);

    // get the index
    _index = accessor!(sib_index: as_ref!(_instr, mod_rm, sib, data)) | 
        (accessor!(rexx: _instr.prefix.kind[PrefixMaskx86::Rex as usize]) << 3);
    match _instr.prefix.vex_type{
        VexExType::EVex=>{
            _index |= accessor!(EVexV2_4_4: _instr.prefix.vex_prefix[3]) << 4;
        },
        _=>{},
    }
    
    match _index {
        0x4=>{
            as_mut!(_instr, mod_rm, sib, sib_index, SibIndexes::NoBase as u8);
        },
        _=>{
            let s = sib_index + _index;
            match s {
                s if s == SibIndexes::Sib as u8 => {
                    as_mut!(_instr, mod_rm, sib, sib_index, SibIndexes::NoBase as u8);
                },
                s if s == SibIndexes::Sib64 as u8 => {
                    as_mut!(_instr, mod_rm, sib, sib_index, SibIndexes::NoBase as u8);
                },
                _=>{ 
                    as_mut!(_instr, mod_rm, sib, sib_index, s); 
                },
            }
        },
    }
    // get the scale
    match accessor!(sib_scale: as_ref!(_instr, mod_rm, sib, data)){
        0=>as_mut!(_instr, mod_rm, sib, sib_scale, 1),
        1=>as_mut!(_instr, mod_rm, sib, sib_scale, 2),
        2=>as_mut!(_instr, mod_rm, sib, sib_scale, 4),
        3=>as_mut!(_instr, mod_rm, sib, sib_scale, 8),
        _=>{},
    }

    // get the base
    _base = accessor!(sib_base: as_ref!(_instr, mod_rm, sib, data)) | 
        (accessor!(rexb: _instr.prefix.kind[PrefixMaskx86::Rex as usize]) << 3);
    
    match _base{
        0x5 | 0xd=>{
            match accessor!(mod: as_ref!(_instr, mod_rm, data)){
                0x0=>{
                    as_mut!(_instr, mod_rm, displacement_ea, EADisplacement::Size32 as u8);
                    as_mut!(_instr, mod_rm, sib, sib_base, 0);
                },
                0x1=>{
                    as_mut!(_instr, mod_rm, displacement_ea, EADisplacement::Size8 as u8);
                    as_mut!(_instr, mod_rm, sib, sib_base, sib_base + _base);
                },
                0x2=>{
                    as_mut!(_instr, mod_rm, displacement_ea, EADisplacement::Size32 as u8);
                    as_mut!(_instr, mod_rm, sib, sib_base, sib_base + _base);
                },
                0x3=>{ return false; },
                _=>{},
            }
        },
        _=>{
            as_mut!(_instr, mod_rm, sib, sib_base, sib_base + _base);
        },
    }
    return true;
}

fn opcode_read_displacement(_instr: &mut Instructionx86) -> bool
{
    disasm_debug!("opcode_read_displacement()");
    match _instr.mod_rm {
        Some(ref mut rm)=>{
            match rm.displacement{
                Some(ref _disp)=>{
                    return true;
                },
                None=>{},
            }
        },
        None=>{},
    }
    // populate displacement struct if not already
    init_displacement(_instr);
    
    //as_mut!(_instr, mod_rm, displacement, offset, (_instr.cursor - _instr.start) as u8);
    match _instr.mod_rm {
        Some(ref mut rm)=>{
            match rm.displacement{
                Some(ref mut disp)=>{
                    disp.offset = (_instr.cursor - _instr.start) as u8;
                },
                None=>{},
            }
        },
        None=>{},
    }
    let mut displ8: i8 = 0;
    let mut displ16: i16 = 0;
    let mut displ32: i32 = 0;
    let mut disp_ea: u8 = 0; 
    match _instr.mod_rm{
        Some(ref rm)=>{
            disp_ea = rm.displacement_ea;
        },
        None=>{},
    }
    disasm_debug!("\tdisp_ea is {:?}", disp_ea);
    match disp_ea{
        disp_ea if disp_ea == EADisplacement::Size0 as u8 =>{},
        disp_ea if disp_ea == EADisplacement::Size8 as u8 =>{
            disasm_debug!("get_int::<i8>");
            if !get_int_signed::<i8>(_instr, &mut displ8){ return false; }
            match _instr.mod_rm {
                Some(ref mut rm)=>{
                    match rm.displacement{
                        Some(ref mut disp)=>{
                            disp.data = displ8 as i32;
                        },
                        None=>{},
                    }
                },
                None=>{},
            }
        },
        disp_ea if disp_ea == EADisplacement::Size16 as u8 =>{
            disasm_debug!("get_int::<i16>");
            if !get_int_signed::<i16>(_instr, &mut displ16){ return false; }
            match _instr.mod_rm {
                Some(ref mut rm)=>{
                    match rm.displacement{
                        Some(ref mut disp)=>{
                            disp.data = displ16 as i32;
                        },
                        None=>{},
                    }
                },
                None=>{},
            }
        },
        disp_ea if disp_ea == EADisplacement::Size32 as u8 =>{
            disasm_debug!("get_int::<i32>");
            if !get_int_signed::<i32>(_instr, &mut displ32){ return false; }
            match _instr.mod_rm {
                Some(ref mut rm)=>{
                    match rm.displacement{
                        Some(ref mut disp)=>{
                            disp.data = displ32 as i32;
                        },
                        None=>{},
                    }
                },
                None=>{},
            }
        },
        _=>{},
    }
    return true;
}

/// address size to get the effective address displacement
fn opcode_check_eff_addr_displacement(
    _instr: &mut Instructionx86, 
    _rm_field: &mut u8,
    _mod_field: &mut u8) -> bool
{
    disasm_debug!("opcode_check_eff_addr_displacement(_rm_field: {:?}, _mod_field: {:?})", _rm_field, _mod_field);
    match _instr.size.address
    {
        2 => {
            match _instr.mod_rm{
                Some( ref mut rm ) => {
                    rm.base_ea_base = EABases::BXSI as u16;
                    rm.kind = RegType::EABases;
                },
                None => {}
            }
            match *_mod_field{
                0x0=>{
                    match *_rm_field{
                        0x6=>{
                            match _instr.mod_rm{
                                Some( ref mut rm ) => {
                                    rm.base_ea = EABases::NoBase as u16;
                                    rm.displacement_ea = EADisplacement::Size16 as u8;
                                },
                                None => {}
                            }
                            if !opcode_read_displacement(_instr){return false;}
                        },
                        _=>{
                            match _instr.mod_rm{
                                Some( ref mut rm ) => {
                                    rm.base_ea = rm.base_ea_base + *_rm_field as u16;
                                    rm.displacement_ea = EADisplacement::Size0 as u8;
                                    rm.kind = RegType::EABases;
                                },
                                None => {}
                            }
                        },
                    }
                },
                0x1=>{
                    match _instr.mod_rm{
                        Some( ref mut rm ) => {
                            rm.base_ea = rm.base_ea_base + *_rm_field as u16;
                            rm.displacement_ea = EADisplacement::Size8 as u8;
                            rm.kind = RegType::EABases;
                        },
                        None => {},
                    }
                    _instr.size.displacement = 1;
                    if !opcode_read_displacement(_instr){return false;}
                },
                0x2=>{
                    match _instr.mod_rm{
                        Some( ref mut rm ) => {
                            rm.base_ea = rm.base_ea_base + *_rm_field as u16;
                            rm.displacement_ea = EADisplacement::Size16 as u8;
                            rm.kind = RegType::EABases;
                        },
                        None => {},
                    }
                    if !opcode_read_displacement(_instr){return false;}
                },
                0x3=>{
                    match _instr.mod_rm{
                        Some( ref mut rm ) => {
                            rm.base_ea = rm.base_ea_reg + *_rm_field as u16;
                            rm.displacement_ea = EADisplacement::Size32 as u8;
                            rm.kind = RegType::AllRegisters;
                        },
                        None => {},
                    }
                    if !opcode_read_displacement(_instr){return false;}
                },
                _=>{},
            }          
        },
        4 | 8 => {
            match _instr.mod_rm {
                Some( ref mut rm ) => {
                    rm.base_ea_base = match _instr.size.address{
                        4=>EABases::EAX as u16,
                        _=>EABases::RAX as u16,
                    };
                },
                None => {},
            }
            match *_mod_field{
                0x0=>{
                    match _instr.mod_rm {
                        Some( ref mut rm ) => {
                            rm.displacement_ea = EADisplacement::Size0 as u8;
                        },
                        None => {},
                    }
                    match *_rm_field{
                        0x14 | 0x4 | 0xc =>{ /* in case REXW.b is set */
                            match _instr.mod_rm {
                                Some( ref mut rm ) => {
                                    rm.base_ea = match _instr.size.address{
                                        4=>EABases::Sib as u16,
                                        _=>EABases::Sib64 as u16,
                                    };
                                    rm.kind = RegType::EABases;
                                },
                                None => {},
                            }
                            if !opcode_read_sib(_instr){return false;}
                            if !opcode_read_displacement(_instr){return false;}
                        },
                        0x5 | 0xd =>{
                            match _instr.mod_rm {
                                Some( ref mut rm ) => {
                                    rm.base_ea = EABases::NoBase as u16;
                                    rm.displacement_ea = EADisplacement::Size32 as u8;
                                },
                                None => {},
                            }
                            if !opcode_read_displacement(_instr){return false;}
                        },
                        _=>{
                            match _instr.mod_rm {
                                Some( ref mut rm ) => {
                                    rm.base_ea = rm.base_ea_base + *_rm_field as u16;
                                },
                                None => {},
                            }
                        },
                    }
                },
                0x1 | 0x2=>{
                    _instr.size.displacement = 1;
                    match _instr.mod_rm {
                        Some( ref mut rm ) => {
                            rm.displacement_ea = match *_mod_field { 0x1=>EADisplacement::Size8 as u8, _=>EADisplacement::Size32 as u8 };
                        },
                        None => {},
                    }
                    match *_rm_field{
                        0x14 | 0x4 | 0xc =>{ /* in case REXW.b is set */
                            match _instr.mod_rm {
                                Some( ref mut rm ) => {
                                    rm.base_ea = EABases::Sib as u16;
                                    rm.kind = RegType::EABases;
                                },
                                None => {},
                            }
                            if !opcode_read_sib(_instr){return false;}
                            if !opcode_read_displacement(_instr){return false;}
                        },
                        _=>{
                            match _instr.mod_rm {
                                Some( ref mut rm ) => {
                                    rm.base_ea = rm.base_ea_base + *_rm_field as u16;
                                    rm.kind = RegType::EABases;
                                },
                                None => {},
                            }
                            if !opcode_read_displacement(_instr){return false;}
                        },
                    }
                },
                0x3=>{
                    match _instr.mod_rm {
                        Some( ref mut rm ) => {
                            rm.base_ea = rm.base_ea_reg + *_rm_field as u16;
                            rm.displacement_ea = EADisplacement::Size0 as u8;
                            rm.kind = RegType::AllRegisters;
                        },
                        None => {},
                    }
                },
                _=>{},
            }            
        },
        _=>{},
    }
    return true;
}

/// Used for determining the operand size
fn opcode_set_operand_size(_instr: &mut Instructionx86)
{
    disasm_debug!("opcode_set_operand_size()");
    match _instr.size.register{
        2 => {
            match _instr.mod_rm{
                Some( ref mut rm ) => {
                    rm.base_reg = AllRegisters::AX  as u16;
                    rm.base_ea_reg = AllRegisters::AX as u16 + EABases::Max as u16; // offset of eabases
                    disasm_debug!("\tbase_ea_reg {:?}", rm.base_ea_reg);
                },
                None => {}
            }
        },
        4 => { 
            match _instr.mod_rm{
                Some( ref mut rm ) => {
                    rm.base_reg = AllRegisters::EAX as u16;
                    rm.base_ea_reg = AllRegisters::EAX as u16 + EABases::Max as u16; // offset of eabases
                    disasm_debug!("\tbase_ea_reg {:?}", rm.base_ea_reg);
                },
                None => {}
            }
        },
        8 => {
            match _instr.mod_rm{
                Some( ref mut rm ) => {
                    rm.base_reg = AllRegisters::RAX as u16;
                    rm.base_ea_reg = AllRegisters::RAX as u16 + EABases::Max as u16; // offset of eabases
                    disasm_debug!("\tbase_ea_reg {:?}", rm.base_ea_reg);
                },
                None => {}
            }
        },
        _=> {
            disasm_debug!("\tunknown register size.");
        },
    }
}
/// Consumes all addressing information (ModR/M byte, SIB byte, and
/// displacement) for an instruction and interprets it.
pub fn opcode_read_modrm(_instr: &mut Instructionx86) -> bool
{
    disasm_debug!("opcode_read_modrm()");
    if _instr.opcode.mod_rm{
        disasm_debug!("\tmod_rm is already set");
        return true;
    }
    // initialize the modrm struct
    init_mod_rm(_instr);
    let mut _byte: u8 = 0;
    let mut _mod_field: u8 = 0;
    let mut _rm_field: u8 = 0;
    let mut _reg_field: u8 = 0;

    // Set mod_rm to true
    _instr.opcode.mod_rm = true;

    // save the mod_rm byte
    if !get_byte(_instr, &mut _byte){ return false; }
    match _instr.mod_rm{
        Some( ref mut rm ) => {
            rm.data = _byte as u16;
        },
        None => {}
    }

    // handle MOV cr/dr/rc/rd
    if _instr.opcode.data[0] == 0x0f 
    && _instr.opcode.kind == OpcodeTypex86::TwoByte 
    && _instr.opcode.data[(_instr.opcode.size-1) as usize] >= 0x20 
    && _instr.opcode.data[(_instr.opcode.size-1) as usize] <= 0x23 
    {
        match _instr.mod_rm{
            Some( ref mut rm ) => rm.data = rm.data | 0xC0,
            None => {}
        }
    }
    _mod_field = accessor!(mod: &_byte);
    _rm_field = accessor!(rm: &_byte);
    _reg_field = accessor!(reg: &_byte);
    // Used for determining the operand size
    opcode_set_operand_size(_instr);
    
    _reg_field |= accessor!(rexr: _instr.prefix.kind[PrefixMaskx86::Rex as usize]) << 3;
    _rm_field |= accessor!(rexb: _instr.prefix.kind[PrefixMaskx86::Rex as usize]) << 3;
    match _instr.prefix.vex_type{
        VexExType::EVex => {
            if _instr.mode == Modex86::Mode64{ // shitty hack
                _reg_field |= accessor!(EVexR2_2_4: _instr.prefix.vex_prefix[1]) << 4;
            }
            _rm_field |= accessor!(EVexX_2_4: _instr.prefix.vex_prefix[1]) << 4;
        },
        _=> {}
    }
    //set the register data
    if _instr.register.is_none(){
        _instr.register = Some(Registerx86{..Default::default()});
    }
    match _instr.register {
        Some(ref mut reg) => {
            match _instr.mod_rm{
                Some( ref rm ) => {
                    reg.data = rm.base_reg as u8 + _reg_field;
                },
                None => {}
            }
        },
        None => {},
    }    
    
    // address size to get the effective address displacement
    if !opcode_check_eff_addr_displacement(
        _instr, 
        &mut _rm_field,
        &mut _mod_field){ 
        disasm_debug!("\tfailed to check ea displacement");
        return false; 
    }

    return true;
}

pub fn opcode_read(_instr: &mut Instructionx86) -> bool
{
    disasm_debug!("opcode_read()");
    let mut _byte: u8 = 0;
    let mut increment = false;
    let vex_type = _instr.prefix.vex_type;
    let vex_prefix = _instr.prefix.vex_prefix[1];
    match vex_type{
        VexExType::EVex => {
            match accessor!(EVexMM_2_4: &vex_prefix){
                vex if vex == VexXopOpcode::Vex0F as u8 => {
                    return opcode_set(_instr, OpcodeTypex86::TwoByte, 0, 0);
                },
                vex if vex == VexXopOpcode::Vex0F38 as u8 => {
                    return opcode_set(_instr, OpcodeTypex86::ThreeByte38, 0, 0);
                },
                vex if vex == VexXopOpcode::Vex0F3A as u8 => {
                    return opcode_set(_instr, OpcodeTypex86::ThreeByte3A, 0, 0);
                },
                _=> { 
                    disasm_debug!("\tVexXopOpcode invalid");
                    return false 
                },
            }
        },
        VexExType::Vex2B => {
            return opcode_set(_instr, OpcodeTypex86::TwoByte, 0x0f, 0);
        },
        VexExType::Vex3B => {
            match accessor!(VexMMMMM_2_3: &vex_prefix){
                vex if vex == VexXopOpcode::Vex0F as u8 => {
                    return opcode_set(_instr, OpcodeTypex86::TwoByte, 0x0f, 0);
                },
                vex if vex == VexXopOpcode::Vex0F38 as u8 => {
                    return opcode_set(_instr, OpcodeTypex86::ThreeByte38, 0x0f, 0x38);
                },
                vex if vex == VexXopOpcode::Vex0F3A as u8 => {
                    return opcode_set(_instr, OpcodeTypex86::ThreeByte3A, 0x0f, 0x3a);
                },
                _=> { 
                    disasm_debug!("\tVexXopOpcode invalid");
                    return false 
                },
            }
        },
        VexExType::Xop => {
            match accessor!(XopMMMMM_2_3: &vex_prefix){
                vex if vex == VexXopOpcode::Xop8 as u8 => {
                    return opcode_set(_instr, OpcodeTypex86::Xop8Map, 0, 0);
                },
                vex if vex == VexXopOpcode::Xop9 as u8 => {
                    return opcode_set(_instr, OpcodeTypex86::Xop9Map, 0, 0);
                },
                vex if vex == VexXopOpcode::XopA as u8 => {
                    return opcode_set(_instr, OpcodeTypex86::XopAMap, 0, 0);
                },
                _=> {
                    disasm_debug!("\tVexXopOpcode invalid");
                    return false
                },
            }
        },
        _=> {},
    }
    if !get_byte(_instr, &mut _byte){ return false;}
    
    // save this byte for MOVcr, MOVdr, MOVrc, MOVrd
    _instr.opcode.data[0] = _byte;
    _instr.opcode.size=1;

    if _byte == 0x0f { 
        _instr.opcode.escape_byte2 = _byte;
        if !get_byte(_instr, &mut _byte){ return false;}
        increment = true;

        match _byte {
            0x38 => {
                _instr.opcode.escape_byte3 = _byte;
                _instr.opcode.kind = OpcodeTypex86::ThreeByte38;
                if !get_byte(_instr, &mut _byte){ return false;}

            },
            0x3a => {
                _instr.opcode.escape_byte3 = _byte;
                _instr.opcode.kind = OpcodeTypex86::ThreeByte3A;
                if !get_byte(_instr, &mut _byte){ return false;}
            },
            0x0e => {
                _instr.opcode.kind = OpcodeTypex86::T3dNowMap;
                // this encode does not have ModRM
                _instr.opcode.mod_rm = true;
            },
            0x0f => {
                _instr.opcode.kind = OpcodeTypex86::T3dNowMap;
                // readModRM
                if !opcode_read_modrm(_instr){ return false;}
                if !get_byte(_instr, &mut _byte){ return false;}
            }
            _=> {
                _instr.opcode.kind = OpcodeTypex86::TwoByte;
            },
        }
            
    }
    if increment{
        _instr.opcode.data[_instr.opcode.size as usize] = _byte;
        _instr.opcode.size += 1;
        disasm_debug!("\topcode is {:?} with size {:?}", _instr.opcode.data, _instr.opcode.size);
    }

    return true;
}