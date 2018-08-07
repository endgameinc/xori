//configuration.rs
use std::path::Path;
use serde_json;

use analysis::analyze::STACK_ADDRESS;
use analysis::analyze::MAX_LOOPS;
use analysis::formats::peloader::DLL_ADDRESS;
use analysis::formats::peloader::DLL_ADDRESS_64;
use analysis::formats::peloader::TEB_ADDRESS;
use analysis::formats::peloader::TEB_ADDRESS_64;
use analysis::formats::peloader::PEB_ADDRESS;
use analysis::formats::peloader::PEB_ADDRESS_64;

#[derive(Debug,Clone,Serialize, Deserialize)]
pub struct Config
{
    pub x86: ConfigX86,
}
impl Config {
    pub fn new()-> Config {
        Config{
            x86: ConfigX86::new(),
        }
    }
}

#[derive(Debug,Clone, Serialize, Deserialize)]
pub struct ConfigX86
{
    pub stack_address: u64,
    pub stack_size: u64,
    pub start_address: u64,
    pub entry_point: u64,
    pub emulation_enabled: bool,
    pub flirt_enabled: bool,
    pub loop_default_case: usize,
    pub pe_file: ConfigPE,
    pub output: ConfigOutput,
}
impl ConfigX86
{
    pub fn new()-> ConfigX86 {
        ConfigX86{
            stack_address: STACK_ADDRESS,
            stack_size: STACK_ADDRESS,
            start_address: 0x1000,
            entry_point: 0,
            emulation_enabled: false,
            flirt_enabled: false,
            loop_default_case: MAX_LOOPS,
            pe_file: ConfigPE::new(),
            output: ConfigOutput::new(),
        }
    }
}
#[derive(Debug,Clone,Serialize, Deserialize)]
pub struct ConfigPE
{
    pub dll_address32: u64,
    pub dll_address64: u64,
    pub teb_address32: u64,
    pub teb_address64: u64,
    pub peb_address32: u64,
    pub peb_address64: u64,
    pub flirt_pat_glob32: String,
    pub flirt_pat_glob64: String,
    pub function_symbol32: String,
    pub function_symbol64: String,
    pub symbol_server: ConfigSymbols
}
impl ConfigPE
{
    pub fn new()-> ConfigPE {
        ConfigPE{
            dll_address32: DLL_ADDRESS,
            dll_address64: DLL_ADDRESS_64,
            teb_address32: TEB_ADDRESS,
            teb_address64: TEB_ADDRESS_64,
            peb_address32: PEB_ADDRESS,
            peb_address64: PEB_ADDRESS_64,
            flirt_pat_glob32: String::from("./FLIRTDB/*/*/*_x86.pat"),
            flirt_pat_glob64: String::from("./FLIRTDB/*/*/*_x64.pat"),
            function_symbol32: String::from("./src/analysis/symbols/generated_user_syswow64.json"),
            function_symbol64: String::from("./src/analysis/symbols/generated_user_system32.json"),
            symbol_server: ConfigSymbols::new(),
        }
    }
}

#[derive(Debug,Clone,Serialize, Deserialize)]
pub struct ConfigSymbols
{
    pub url: String,
    pub user_agent: String,
    pub dll_folder32: String,
    pub dll_folder64: String,
}
impl ConfigSymbols
{
    pub fn new()-> ConfigSymbols {
        ConfigSymbols{
            url: String::new(),
            user_agent: String::new(),
            dll_folder32: String::new(),
            dll_folder64: String::new(),
        }
    }
}

#[derive(Debug,Clone,Serialize, Deserialize)]
pub struct ConfigOutput
{
    pub functions: bool,
    pub disassembly: bool,
    pub disasm_json: bool,
    pub imports: bool
}
impl ConfigOutput
{
    pub fn new()-> ConfigOutput {
        ConfigOutput{
            functions: true,
            disassembly: true,
            disasm_json: true,
            imports: true
        }
    }
}

pub fn read_config(path: &Path) -> Config
{
    let config_file = ::std::fs::File::open(path).expect("failed to open the file");
    let mut config: Config = Config::new(); 
    match serde_json::from_reader(config_file)
    {
        Ok(c)=>{
            config = c;
        },
        _=>{
            println!("Could not parse json config");
        },
    }
    return config;
}
