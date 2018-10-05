//simple_binx86.rs
extern crate xori;
extern crate serde_json;
use std::path::Path;
use xori::analysis::analyze::analyze;
use xori::disasm::*;
use xori::configuration::*;

fn main() 
{
	let mut binary32= b"\xe9\x1e\x00\x00\x00\xb8\x04\
    \x00\x00\x00\xbb\x01\x00\x00\x00\x59\xba\x0f\
    \x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\
    \x00\x00\x00\x00\xcd\x80\xe8\xdd\xff\xff\xff\
    \x48\x65\x6c\x6c\x6f\x2c\x20\x57\x6f\x72\x6c\
    \x64\x21\x0d\x0a".to_vec();

    let mut config_map: Config = Config::new();
    if Path::new("xori.json").exists()
    {
        config_map = read_config(&Path::new("xori.json"));
    } 

	match analyze(&Arch::ArchX86, &Mode::Mode32, &mut binary32, &config_map)
    {
        Some(analysis)=>{
            if !analysis.disasm.is_empty(){
                println!("{}", analysis.disasm);
            }
        },
        None=>{},
    }
}