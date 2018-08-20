extern crate colored;
extern crate num;
extern crate nom;
extern crate argparse;
extern crate xori;
extern crate memmap;
extern crate serde_json;
extern crate uuid;

use xori::disasm::*;
use xori::configuration::*;
use xori::analysis::analyze::*;
use memmap::MmapMut;
use argparse::{ArgumentParser, Store, StoreTrue};
use std::path::Path;
use std::fs::OpenOptions;
use std::fs::File;
use std::io::Read;
use std::fs;
use std::env;
use std::io::Write;


fn main() 
{
    let mut input_path: String = String::new();
    let mut output_path: String = String::new();
    let mut config_file: String = String::new();
    let mut config_mode: String = String::new();
    let mut uuid_name: bool = false;

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("disassembly files and output json");
        ap.refer(&mut input_path)
        .add_option(
            &["--input-file", "-f"],
            Store,
            "path of the file to disassemble")
        .required();

        ap.refer(&mut output_path)
        .add_option(
            &["--output", "-o"],
            Store,
            "path of the output json");

        ap.refer(&mut config_mode)
        .add_option(
            &["--mode", "-m"],
            Store,
            "mode of the disassembly [ Mode16, Mode32, Mode64 ]");

        ap.refer(&mut config_file).add_option(
            &["--config", "-c"],
            Store,
            "load a specific configuration or else default values are used.",
        );

        ap.refer(&mut uuid_name).add_option(
            &["--uuid", "-u"],
            StoreTrue,
            "create uuids for output files instead of suffixing the input filename",
        );
        ap.parse_args_or_exit();
    }

    // Verify input path
    let path = Path::new(&input_path);
    if !path.exists() || !path.is_file(){
        eprintln!("error: file does not exist");
        std::process::exit(1);
    }

    // Verify output path
    let current_dir = env::current_dir().unwrap();
    let mut output_folder = Path::new(&output_path);
    if !output_folder.exists() && !output_folder.is_dir(){
        eprintln!("error: folder does not exist, using current_dir");
        output_folder = current_dir.as_path();
    }

    let mut config_map: Config = Config::new();
    let conf_path = Path::new(&config_file);
    if conf_path.exists()
    {
        config_map = read_config(&conf_path);
    } 
    else if Path::new("xori.json").exists()
    {
        config_map = read_config(&Path::new("xori.json"));
    } 
    else {
        println!("error: config file does not exist, using default configurations.");
    }

    let metadata = fs::metadata(&path).expect("failed to read file metadata");
    let mut file;
    let mut buffer;
    let readonly;

    file = match OpenOptions::new()
                       .read(true)
                       .write(true)
                       .open(&path) {
        Ok(file) => {readonly = false; file},
        Err(_) => {readonly = true; OpenOptions::new()
                       .read(true)
                       .write(false)
                       .open(&path).expect("failed to open file readonly") },
    };

    if readonly {
        let len = metadata.len();
        buffer = MmapMut::map_anon(len as usize).expect("failed to create anon map for readonly file");
        let mut prebuf = vec![];
        file.read_to_end(&mut prebuf).expect("failed to read readonly file");
        buffer[..len as usize].copy_from_slice(&prebuf[..len as usize]);
    } else {
        buffer = unsafe { MmapMut::map_mut(&file).expect("failed to map the file")};
    }

    // Used for BIN only
    let option_mode: Mode = match config_mode.as_str() {
        "Mode16" => Mode::Mode16,
        "Mode32" => Mode::Mode32,
        "Mode64" => Mode::Mode64,
        _=> Mode::Mode32, //Default
    };

    match analyze(&Arch::ArchX86, &option_mode, &mut buffer, &config_map)
    {
        Some(analysis)=>{
            
            let filename;
            filename = match uuid_name { true => format!("{}",uuid::Uuid::new_v4()), false => String::from(path.file_name().unwrap().to_str().unwrap())};
            if !analysis.disasm.is_empty(){
                let disasm_output = format!("{}_disasm.json", filename);
                let disasm_path = output_folder.join(disasm_output);
                let mut diasm_file = File::create(disasm_path)
                    .expect("error: Could not create json file");
                let _result = diasm_file.write_all(analysis.disasm.as_bytes());
            }
            if !analysis.functions.is_empty(){
                let func_output = format!("{}_functions.json", filename);
                let func_path = output_folder.join(func_output);
                let mut func_file = File::create(func_path)
                    .expect("error: Could not create json file");
                let _result = func_file.write_all(analysis.functions.as_bytes());
            }
            if !analysis.header.is_empty(){
                let header_output = format!("{}_header.json", filename);
                let header_path = output_folder.join(header_output);
                let mut header_file = File::create(header_path)
                    .expect("error: Could not create json file");
                let _result = header_file.write_all(analysis.header.as_bytes());
            }
        },
        None=>{},
    }
}
