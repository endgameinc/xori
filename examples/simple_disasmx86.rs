extern crate xori;
use std::fmt::Write;
use xori::disasm::*;
use xori::arch::x86::archx86::X86Detail;

fn hex_array(
    arr: &[u8; 16], 
    len: usize) -> String 
{
    let mut s = String::new();
    for i in 0..len 
    {
        let byte = arr[i];
        write!(&mut s, "{:02X} ", byte).expect("Unable to write");
    }
    return s;
}

fn main() 
{
	let xi = Xori { arch: Arch::ArchX86, mode: Mode::Mode32 };

	let binary32 = b"\xe9\x1e\x00\x00\x00\xb8\x04\
    \x00\x00\x00\xbb\x01\x00\x00\x00\x59\xba\x0f\
    \x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\
    \x00\x00\x00\x00\xcd\x80\xe8\xdd\xff\xff\xff\
    \x48\x65\x6c\x6c\x6f\x2c\x20\x57\x6f\x72\x6c\
    \x64\x21\x0d\x0a";
	
	let mut vec: Vec<Instruction<X86Detail>> = Vec::new();
    let start_address = 0x1000;
	xi.disasm(binary32, binary32.len(), start_address, start_address, 0, &mut vec);

	if vec.len() > 0
    {
    	//Display values
    	for instr in vec.iter_mut()
    	{
    	    let addr: String = format!("0x{:x}", instr.address);
    	    println!("{:16} {:20} {} {}", 
    	        addr, 
    	        hex_array(&instr.bytes, instr.size),
    	        instr.mnemonic,
    	        instr.op_str);
    	}
    }
}