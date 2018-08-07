//flirtunzip.rs
extern crate memmap;
extern crate bincode;
extern crate flate2;
#[macro_use]
extern crate serde_derive;
use memmap::Mmap;
use std::env;
use std::fs::File;
use flate2::bufread::ZlibDecoder;
use std::io::prelude::*;
use bincode::serialize;
use std::path::Path;

#[macro_use]
extern crate nom;
use nom::{le_u8, le_u16, le_u32, is_alphanumeric};

const _IDASIG__FEATURE__STARTUP: usize = 0x0;
const _IDASIG__FEATURE__CTYPE_CRC: usize = 0x0;
const _IDASIG__FEATURE__2BYTE_CTYPE: usize = 0x0;
const _IDASIG__FEATURE__ALT_CTYPE_CRC: usize = 0x0;
const _IDASIG__FEATURE__COMPRESSED: usize = 0x1;

#[derive(Debug,PartialEq)]
pub enum IdaArchType
{
	//"Intel 80x86"
	Intel80X86 = 0x00,
	//"8085, Z80"
	Z80 = 0x01,
	//"Intel 860"
	Intel860 = 0x02,
	//"8051"
	Arch8051 = 0x03,
	//"TMS320C5x"
	TMS320C5X = 0x04,
	//"6502"
	Arch6502 = 0x05,
	//"PDP11"
	PDP11 = 0x06,
	//"Motorola 680x0"
	Motorola680x0 = 0x07,
	//"Java"
	JAVA = 0x08,
	//"Motorola 68xx"
	Motorola68xx = 0x09,
	//"SGS-Thomson ST7"
	SgsThomsonSt7 = 0x0A,
	//"Motorola 68HC12"
	Motorola68hc12 = 0x0B,
	//"MIPS"
	MIPS = 0x0C,
	//"Advanced RISC Machines"
	AdvancedRisc = 0x0D,
	//"TMS320C6x"
	TMS320C6X = 0x0E,
	//"PowerPC"
	POWERPC = 0x0F,
	//"Intel 80196"
	Intel80196 = 0x10,
	//"Z8"
	Z8 = 0x11,
	//"Hitachi SH"
	HitachiSh = 0x12,
	//"Microsoft Visual Studio.Net"
	MsvsDotNet = 0x13,
	//"Atmel 8-bit RISC processor(s)"
	Atmel8BitRisc = 0x14,
	//"Hitachi H8/300, H8/2000"
	HitachiH8300H82000 = 0x15,
	//"Microchip's PIC"
	MicrochipPic = 0x16,
	//"SPARC"
	SPARC = 0x17,
	//"DEC Alpha"
	DecAlpha = 0x18,
	//"Hewlett-Packard PA-RISC"
	HpPaRisc = 0x19,
	//"Hitachi H8/500"
	HitachiH8500 = 0x1A,
	//"Tasking Tricore"
	TaskingTricore = 0x1B,
	//"Motorola DSP5600x"
	MotorolaDsp5600x = 0x1C,
	//"Siemens C166 family"
	SiemensC166 = 0x1D,
	//"SGS-Thomson ST20"
	SgsThomsonSt20 = 0x1E,
	//"Intel Itanium IA64"
	IntelItaniumIa64 = 0x1F,
	//"Intel 960"
	IntelI960 = 0x20,
	//"Fujistu F2MC-16"
	FujitsuF2mc16 = 0x21,
	//"TMS320C54xx"
	TMS320C54XX = 0x22,
	//"TMS320C55xx"
	TMS320C55XX = 0x23,
	//"Trimedia"
	TRIMEDIA = 0x24,
	//"Mitsubishi 32bit RISC"
	Mitsubish32bitrisc = 0x25,
	//"NEC 78K0"
	Nec78k0 = 0x26,
	//"NEC 78K0S"
	Nec78k0s = 0x27,
	//"Mitsubishi 8bit"
	Mitsubishi8bit = 0x28,
	//"Mitsubishi 16bit"
	Mitsibushi16bit = 0x29,
	//"ST9+"
	ST9PLUS = 0x2A,
	//"Fujitsu FR Family"
	FUJITSUFR = 0x2B,
	//"Motorola 68HC16"
	Motorola68hc16 = 0x2C,
	//"Mitsubishi 7900"
	Mitsubishi7900 = 0x2D,
	INVALID,
}

fn show_arch(value: u8) -> IdaArchType
{
	return match value
	{
		0x00 => IdaArchType::Intel80X86,
		0x01 => IdaArchType::Z80,
		0x02 => IdaArchType::Intel860,
		0x03 => IdaArchType::Arch8051,
		0x04 => IdaArchType::TMS320C5X,
		0x05 => IdaArchType::Arch6502,
		0x06 => IdaArchType::PDP11,
		0x07 => IdaArchType::Motorola680x0,
		0x08 => IdaArchType::JAVA,
		0x09 => IdaArchType::Motorola68xx,
		0x0A => IdaArchType::SgsThomsonSt7,
		0x0B => IdaArchType::Motorola68hc12,
		0x0C => IdaArchType::MIPS,
		0x0D => IdaArchType::AdvancedRisc,
		0x0E => IdaArchType::TMS320C6X,
		0x0F => IdaArchType::POWERPC,
		0x10 => IdaArchType::Intel80196,
		0x11 => IdaArchType::Z8,
		0x12 => IdaArchType::HitachiSh,
		0x13 => IdaArchType::MsvsDotNet,
		0x14 => IdaArchType::Atmel8BitRisc,
		0x15 => IdaArchType::HitachiH8300H82000,
		0x16 => IdaArchType::MicrochipPic,
		0x17 => IdaArchType::SPARC,
		0x18 => IdaArchType::DecAlpha,
		0x19 => IdaArchType::HpPaRisc,
		0x1A => IdaArchType::HitachiH8500,
		0x1B => IdaArchType::TaskingTricore,
		0x1C => IdaArchType::MotorolaDsp5600x,
		0x1D => IdaArchType::SiemensC166,
		0x1E => IdaArchType::SgsThomsonSt20,
		0x1F => IdaArchType::IntelItaniumIa64,
		0x20 => IdaArchType::IntelI960,
		0x21 => IdaArchType::FujitsuF2mc16,
		0x22 => IdaArchType::TMS320C54XX,
		0x23 => IdaArchType::TMS320C55XX,
		0x24 => IdaArchType::TRIMEDIA,
		0x25 => IdaArchType::Mitsubish32bitrisc,
		0x26 => IdaArchType::Nec78k0,
		0x27 => IdaArchType::Nec78k0s,
		0x28 => IdaArchType::Mitsubishi8bit,
		0x29 => IdaArchType::Mitsibushi16bit,
		0x2A => IdaArchType::ST9PLUS,
		0x2B => IdaArchType::FUJITSUFR,
		0x2C => IdaArchType::Motorola68hc16,
		0x2D => IdaArchType::Mitsubishi7900,
		_=> IdaArchType::INVALID,
	}
}

#[derive(Debug,PartialEq)]
pub enum IdaOsType {
	INVALID,
	MSDOS = 0x1,
	WIN = 0x2,
	OS2 = 0x4,
	NETWARE= 0x8,
	UNIX= 0x10,
}

fn show_os(value: u16) -> IdaOsType{
	return match value
	{
		0x1=>IdaOsType::MSDOS,
		0x2=>IdaOsType::WIN,
		0x4=>IdaOsType::OS2,
		0x8=>IdaOsType::NETWARE,
		0x10=>IdaOsType::UNIX,
		_=>IdaOsType::INVALID,
	}
}

#[derive(Debug,PartialEq)]
pub enum IdaFileType{
	INVALID,
	DosExeOld = 0x00000001,
	DosComOld = 0x00000002,
	BIN = 0x00000004,
	DOSDRV = 0x00000008,
	NE = 0x00000010,
	INTELHEX = 0x00000020,
	MOSHEX = 0x00000040,
	LX = 0x00000080,
	LE = 0x00000100,
	NLM = 0x00000200,
	COFF = 0x00000400,
	PE = 0x00000800,
	OMF = 0x00001000,
	SREC = 0x00002000,
	ZIP = 0x00004000,
	OMFLIB = 0x00008000,
	AR = 0x00010000,
	LOADER = 0x00020000,
	ELF = 0x00040000,
	W32RUN = 0x00080000,
	AOUT = 0x00100000,
	PILOT = 0x00200000,
	DosExe = 0x00400000,
	AIXAR = 0x00800000,
}
 
fn show_type(value: u32) -> IdaFileType
{
	return match value
	{
		0x00000001 => IdaFileType::DosExeOld,
		0x00000002 => IdaFileType::DosComOld,
		0x00000004 => IdaFileType::BIN,
		0x00000008 => IdaFileType::DOSDRV,
		0x00000010 => IdaFileType::NE,
		0x00000020 => IdaFileType::INTELHEX,
		0x00000040 => IdaFileType::MOSHEX,
		0x00000080 => IdaFileType::LX,
		0x00000100 => IdaFileType::LE,
		0x00000200 => IdaFileType::NLM,
		0x00000400 => IdaFileType::COFF,
		0x00000800 => IdaFileType::PE,
		0x00001000 => IdaFileType::OMF,
		0x00002000 => IdaFileType::SREC,
		0x00004000 => IdaFileType::ZIP,
		0x00008000 => IdaFileType::OMFLIB,
		0x00010000 => IdaFileType::AR,
		0x00020000 => IdaFileType::LOADER,
		0x00040000 => IdaFileType::ELF,
		0x00080000 => IdaFileType::W32RUN,
		0x00100000 => IdaFileType::AOUT,
		0x00200000 => IdaFileType::PILOT,
		0x00400000 => IdaFileType::DosExe,
		0x00800000 => IdaFileType::AIXAR,
		_=>IdaFileType::INVALID,
	}
}
#[derive(Debug,PartialEq)]
pub enum IdaAppType
{
	NONE,
	CONSOLE = 0x0001,
	GRAPHICS = 0x0002,
	EXE = 0x0004,
	DLL = 0x0008,
	DRV = 0x0010,
	SINGLETHREADED = 0x0020,
	MULTITHREADED = 0x0040,
	App16BIT = 0x0080,
	App32BIT = 0x0100,
	App64BIT = 0x0200,
}

fn show_app(value: u16) -> Vec<IdaAppType>
{
	let mut apps: Vec<IdaAppType> = Vec::new();
	if value & 0x0001 == 0x0001 { apps.push(IdaAppType::CONSOLE) }
	if value & 0x0002 == 0x0002 { apps.push(IdaAppType::GRAPHICS)}
	if value & 0x0004 == 0x0004 { apps.push(IdaAppType::EXE)}
	if value & 0x0008 == 0x0008 {apps.push(IdaAppType::DLL)}
    if value & 0x0010 == 0x0010 {apps.push(IdaAppType::DRV)}
	if value & 0x0020 == 0x0020 {apps.push(IdaAppType::SINGLETHREADED)}
	if value & 0x0040 == 0x0040 {apps.push(IdaAppType::MULTITHREADED)}
	if value & 0x0080 == 0x0080 {apps.push(IdaAppType::App16BIT)}
	if value & 0x0100 == 0x0100 {apps.push(IdaAppType::App32BIT)}
	if value & 0x0200 == 0x0200 {apps.push(IdaAppType::App64BIT)}

	return apps;
}

#[derive(Debug,PartialEq, Serialize)]
pub struct FlirtSigHeader {
    pub version: u8,
    pub processor: u8,
    pub file_types: u32,
    pub os_types: u16,
    pub app_types: u16,
    pub feature_flags: u8,
    pub pad: u8,
    pub old_number_modules: u16,
    pub crc16: u16,
    pub _ctype: u8,
    pub library_name_sz: u8,
    pub alt_ctype_crc: u16,
    pub n_modules: u32,
    pub unknown: u32,
    pub name: String,
}


named!(sig_header<&[u8], FlirtSigHeader>,
  do_parse!(
    tag!([0x49,0x44,0x41,0x53,0x47,0x4e]) >>
    version: le_u8 >>
    processor: le_u8 >>
    file_types: le_u32 >>
    os_types: le_u16 >>
    app_types: le_u16 >>
    feature_flags: le_u8 >>
    pad: le_u8 >>
    old_number_modules: le_u16 >>
    crc16: le_u16 >>
    _ctype: is_a!([0x00]) >>
    library_name_sz: le_u8 >>
    alt_ctype_crc: le_u16 >>
    n_modules: le_u32 >>
    unknown: le_u32 >>
    take_till!(|ch| is_alphanumeric(ch)) >>
    name: take!(library_name_sz) >>
    (FlirtSigHeader{
    version,
    processor,
    file_types,
    os_types,
    app_types,
    feature_flags,
    pad,
    old_number_modules,
    crc16,
    _ctype: 0,
    library_name_sz,
    alt_ctype_crc,
    n_modules,
    unknown,
    name: String::from_utf8(name.to_vec()).unwrap_or("no name".to_string()),
    })
  )
);


fn main() {
    let path = env::args()
        .nth(1)
        .expect("supply a single path as the program argument");

    let input_path = Path::new(&path);
    let output_path = String::from(input_path
                            .file_name().unwrap().to_str().unwrap_or(""));
    let file = File::open(input_path).expect("failed to open the file");
    let mmap = unsafe { Mmap::map(&file).expect("failed to map the file") };
    match sig_header(&mmap)
    {
    	Ok((_i, mut header))=>{
    		if !header.version == 0xA
    		{
    			println!("Version is not Supported.");
    		}
    		if header.feature_flags & 0x10 == 0x10
    		{
    			let mut decoder = ZlibDecoder::new(_i);
    			let mut ret = Vec::new();
   				decoder.read_to_end(&mut ret).unwrap();
    			//println!("{}", ret.to_hex(16));
    			header.feature_flags ^= 0x10;
    			let mut uncompressed: Vec<u8> = vec![0x49,0x44,0x41,0x53,0x47,0x4e];
    			let mut uncompressed_header: Vec<u8> = serialize(&header).unwrap();
    			uncompressed.append(&mut uncompressed_header);
    			uncompressed.append(&mut ret);
    			let mut f = File::create(&output_path)
            		.expect("error: filed to create file");
        		let _result = f.write_all(&uncompressed);
        		println!("This sig file {} has been decompressed.", output_path);
        		
    		} else
    		{
    			println!("This sig file is already decompressed.");
    		}
    		println!("Version: {}", header.version);
    		println!("Processor: {:?}", show_arch(header.processor));
    		println!("File Type: {:?}", show_type(header.file_types));
    		println!("OS Type: {:?}", show_os(header.os_types));
    		println!("App Type: {:?}", show_app(header.app_types));
    		println!("Feature Flags: {}", header.feature_flags);
    		println!("Old Num of Modules: {}", header.old_number_modules);
    		println!("CRC16: {}", header.crc16);
    		println!("CType: {}", header._ctype);
    		println!("Alt Ctype: {}", header.alt_ctype_crc);
    		println!("Num of Modules: {}", header.n_modules);
    		println!("Name: {}", header.name);
    	},
    	Err(_e)=>println!("This is not a sig file."),
    }
}