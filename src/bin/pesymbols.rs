//pesymbols.rs
extern crate serde;
extern crate serde_json;
extern crate argparse;
extern crate memmap;
use memmap::Mmap;
extern crate reqwest;
extern crate url;
extern crate pdb;
#[macro_use]
extern crate nom;
use nom::{be_u64, le_u32, le_u16};
extern crate xori;
use xori::configuration::*;
use xori::analysis::formats::pe::*;
use xori::arch::x86::analyzex86::{Symbol, Export, ExportDirectory};
extern crate base64;

use std::path::Path;
use argparse::{ArgumentParser, Store};
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::Read;
use url::Url;
use reqwest::Client;
use reqwest::header::USER_AGENT;

#[allow(dead_code)]
fn download_pdb(
    url: &String,
    user_agent: &String,
    _dll_basename: &String,
    pdb_name: &String,
    guid: &String,
    output_dir: &Path) -> Option<::std::path::PathBuf>
{
    let mut output_pdb = pdb_name.clone();
    output_pdb.pop();
    output_pdb.push('_');
    let output_path = Path::new(output_dir).join(output_pdb);

    // If the pdb already exists
    if output_path.exists()
    {
        return Some(output_path);
    }

    let url = Url::parse(&format!("{}{}/{}/{}",url, pdb_name, guid, pdb_name))
        .expect("error: Url perser failed");
    println!("{}\n{}", url, user_agent);
    let mut response = Client::new()
            .get(url)
            .header(USER_AGENT, &*user_agent)
            .send()
            .expect("Failed to send request");
    if response.status() == reqwest::StatusCode::OK
    {
        let mut buffer: Vec<u8> = Vec::new();
        response.read_to_end(&mut buffer)
            .expect("Failed to read response");

        let mut f = File::create(&output_path)
            .expect("error: filed to create file");
        let _result = f.write_all(&buffer);
    } else {
        println!("error: response failed. {:?}", response.status());
        return None;
    }
    return Some(output_path);
}

fn extract_exports(dll_path: &Path) -> Option<(Vec<Export>, SectionTable, String, ExportDirectory)>
{
    let file = std::fs::File::open(dll_path).expect("failed to open the file");
    let mmap = unsafe { Mmap::map(&file).expect("failed to map the file") };


    let pe_offset;
    let mut dll_exports: Vec<Export> = Vec::new();
    match dos_header(&mmap){
      Ok((_cursor, o))=> {
        pe_offset = o.e_lfanew as usize;
      },
      _=> {
        println!("error or incomplete DOS Header");
        panic!("cannot parse DOS Header");
      }
    }
    let export_table_offset;
    let export_table_size;
    let _bits;
    match pe_header(&mmap[pe_offset..])
    {
        Ok((cursor, peh)) => {
            match peh.image_optional_header {
                ImageOptionalHeaderKind::Pe32(ioh) => {
                    export_table_offset = ioh.image_data_directory[ImageDataIndex::ExportTable as usize]
                        .virtual_address;
                    export_table_size = ioh.image_data_directory[ImageDataIndex::ExportTable as usize]
                        .size;
                    _bits = 32;
                }
                ImageOptionalHeaderKind::Pe32Plus(ioh) => {
                    export_table_offset = ioh.image_data_directory[ImageDataIndex::ExportTable as usize]
                        .virtual_address;
                    export_table_size = ioh.image_data_directory[ImageDataIndex::ExportTable as usize]
                        .size;
                    _bits = 64;
                }
            }

            let dll_section_table: SectionTable = match section_table(cursor, peh.coff_header.num_sections)
            {
                Ok((_i, section_table))=>section_table,
                Err(_err)=> return None,
            };

            let (header_copy, export_dir) = build_dll_header_with_exportrva(
                &mmap,
                export_table_offset as usize,
                rva_to_file_offset(export_table_offset as usize, &dll_section_table) as usize,
                export_table_size as usize);

            let export_descriptor: ImageExportDescriptor = match image_export_descriptor(
                &mmap[rva_to_file_offset(export_table_offset as usize, &dll_section_table)..])
            {
                Ok((_i, export_desc))=> export_desc,
                Err(_err)=> return None,
            };

            let _dllname = match import_dll_name(
                &mmap[rva_to_file_offset(export_descriptor.name as usize, &dll_section_table,)..],)
            {
                Ok((_i, dllname)) => dllname,
                Err(_err)=> return None,
            };

            let address_of_functions = match export_table_entry(
                &mmap[rva_to_file_offset(export_descriptor.address_of_functions as usize, &dll_section_table,)..],
                export_descriptor.number_of_functions as usize)
            {
                Ok((_i, func_addr)) => func_addr,
                Err(_err)=> return None,
            };

            let address_of_names = match export_table_entry(
                &mmap[rva_to_file_offset(export_descriptor.address_of_names as usize, &dll_section_table,)..],
                export_descriptor.number_of_names as usize)
            {
                Ok((_i, addr_names)) => addr_names,
                Err(_err)=> return None,
            };

            let address_of_name_ordinals = match export_table_ord(
                &mmap[rva_to_file_offset(export_descriptor.address_of_name_ordinals as usize, &dll_section_table,)..],
                export_descriptor.number_of_names as usize)
            {
                Ok((_i, func_addr)) => func_addr,
                Err(_err)=> return None,
            };

            for i in 0..export_descriptor.number_of_names as usize
            {
                let mut forwarder = false;
                let mut forwarder_name = String::new();
                let name_addr = address_of_names.as_slice()[i];
                let func_ordinal = address_of_name_ordinals.as_slice()[i];
                let func_addr = address_of_functions.as_slice()[func_ordinal as usize];
                // check forwarder
                if func_addr >= export_table_offset &&
                    func_addr < export_table_offset+export_table_size
                {
                    forwarder = true;
                    forwarder_name = match import_dll_name(
                        &mmap[rva_to_file_offset(func_addr as usize, &dll_section_table,)..],)
                    {
                        Ok((_i, export_name)) => export_name.name,
                        Err(_err)=>String::new(),
                    };

                }

                let export_name = match import_dll_name(
                    &mmap[rva_to_file_offset(name_addr as usize, &dll_section_table,)..],)
                {
                    Ok((_i, export_name)) => export_name.name,
                    Err(_err)=>String::new(),
                };
                dll_exports.push(
                    Export
                    {

                        name: export_name,
                        rva: func_addr as u64,
                        ordinal: func_ordinal + export_descriptor.base as u16,
                        forwarder: forwarder,
                        forwarder_name: forwarder_name,
                    });
            }
            return Some((dll_exports, dll_section_table,header_copy, export_dir));
        },
        _=>{},
    }
    return None;
}

/*
fn extract_symbols(output_path: &Path, section_table: &SectionTable) -> Vec<Exports>
{
    //parse the PDB file
    let file = std::fs::File::open(output_path)
        .expect("error: PDB file failed to open");

    let mut pdb = pdb::PDB::open(file).expect("error: PDB parser failed");

    let symbol_table = pdb.global_symbols()
        .expect("error: PDB global symbols failed");

    let mut symbols = symbol_table.iter();
    let mut exports: Vec<Exports> = Vec::new();
    while let Some(symbol) = symbols.next()
        .expect("error: PDB could not get next symbol")
    {

        match symbol.parse()
        {
            Ok(pdb::SymbolData::PublicSymbol(data)) =>
            {
                /* For Reference
                pub struct PublicSymbol {
                    pub code: bool,
                    pub function: bool,
                    pub managed: bool,
                    pub msil: bool,
                    pub offset: u32,
                    pub segment: u16,
                }*/

                let mut function_name = String::from(symbol.name()
                    .expect("failed to get symbol name").to_string());
                /*let mut truncated_name = function_name.clone();

                if function_name.starts_with("_") && function_name.contains("@")
                {
                    function_name.remove(0);
                    let trunc: Vec<&str> = function_name.split('@').collect();
                    truncated_name = String::from(trunc[0]);
                }
                //if !(truncated_name.starts_with("?") || truncated_name.starts_with("@"))
                //{
                    let section_offset = (data.segment-2) as usize;
                    if section_offset < section_table.section_headers.len()
                    {
                        let section_vaddr = section_table.section_headers[section_offset].virtual_address;
                        let export_vaddr = (data.offset + section_vaddr) as usize;
                        println!("pdb name: {} vaddr: 0x{:x}", function_name, export_vaddr);
                        exports.push(Exports
                        {
                            function: String::from(function_name),
                            rva: export_vaddr,
                        });
                    }
                //}
                */
                println!("pdb name: {} data: {:?}", function_name, data);
                        exports.push(Exports
                        {
                            function: String::from(function_name),
                            rva: data.offset as usize,
                        });

            },
            _ => {},
        }
    }
    return exports;
}
*/


/*
0  4  Signature  0x52 0x53 0x44 0x53 (ASCII string: "RSDS")
4  16  Guid  GUID (Globally Unique Identifier) of the associated PDB.
20  4  Age  Iteration of the PDB. The first iteration is 1.
        The iteration is incremented each time the PDB content is augmented.
24    Path  UTF-8 NUL-terminated path to the associated .pdb file
*/
#[derive(Debug)]
pub struct PdbDir {
    guid: String,
    path: String
}

#[allow(dead_code)]
fn get_guid(path: &Path) -> PdbDir
{
    let file = File::open(path)
        .expect("failed to open the file");
    let mmap = unsafe { Mmap::map(&file)
        .expect("failed to map the file") };
    named!(find_dir, take_until_and_consume!("RSDS"));
    named!(guid<&[u8], (u32, u16, u16, u64, u32) >,
    /* todo name these... there is a from MS generator hiding
    in this PR if we want to name the chunks
    https://github.com/dotnet/roslyn/issues/926 */
      tuple!(
        le_u32,
        le_u16,
        le_u16,
        be_u64,
        le_u32
      )
    );

    named!(pdb_path<&[u8], &[u8]>,
           take_until_and_consume!("\0"));
    let res = find_dir(&mmap);
    let guid_res;
    match res {
        Ok((i, _o)) => { guid_res = guid(i).unwrap() }
        _ => return PdbDir{ guid: "".to_string(), path: "".to_string() }
        }
    // guid_res.1 is the match of the guid! macro, guid_res.0 is the rest after it
    return PdbDir {
     guid: format!("{:08X}{:04X}{:04X}{:08X}{}",
        (guid_res.1).0,
        (guid_res.1).1,
        (guid_res.1).2,
        (guid_res.1).3,
        (guid_res.1).4), // assuming this is an int value not a hex value
     path: String::from_utf8(pdb_path(guid_res.0)
        .unwrap().1.to_vec()).unwrap_or("".to_string())
    }
}

fn build_dll_header_with_exportrva(
    _binary: &[u8],
    export_table_rva: usize,
    export_table_offset: usize,
    export_table_size: usize) -> (String, ExportDirectory)
{
    // only collect 0x300 bytes
    let length = 0x320;
    let mut new_header: Vec<u8> = Vec::with_capacity(length);
    let mut new_exp_dir: Vec<u8> = Vec::with_capacity(export_table_size);
    new_header.extend_from_slice(&_binary[0..length]);

    let export_table_length = export_table_offset + export_table_size;
    new_exp_dir.extend_from_slice(&_binary[export_table_offset..export_table_length]);
    //println!("{}", &new_exp_dir[0..export_table_size].to_hex(16));
    let header_encoded = base64::encode(&new_header);
    let export_dir_encoded = base64::encode(&new_exp_dir);
    return (header_encoded, ExportDirectory{
        offset: export_table_rva,
        size: export_table_size,
        data_b64: export_dir_encoded,
        data: Vec::new(),
    })
}

fn main()
{
    let mut config_file: String = String::new();

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("downloads pdb files to output json");

        ap.refer(&mut config_file).add_option(
            &["--config", "-c"],
            Store,
            "load a specific configuration or else default values are used.",
        );
        ap.parse_args_or_exit();
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

    let _url = config_map.x86.pe_file.symbol_server.url;
    let _url = config_map.x86.pe_file.symbol_server.user_agent;
    let dllfolder32 = config_map.x86.pe_file.symbol_server.dll_folder32;
    let dllfolder64 = config_map.x86.pe_file.symbol_server.dll_folder64;
    let dll32 = Path::new(&dllfolder32);
    let dll64 = Path::new(&dllfolder64);

    if dll32.exists()
    {
        println!("Getting 32bit symbols.");
        let mut symbols32: Vec<Symbol> = Vec::new();
        let paths = fs::read_dir(dll32).expect("error: dll folder32 is empty");
        for path in paths
        {
            // TODO handle unwrap
            let dll_path = path.unwrap().path();
            match dll_path.extension()
            {
                Some(ref extension)=>{
                    if *extension == "dll"
                    {
                        let (dll_exports, _section_table, header_copy, export_dir) = match extract_exports(&dll_path)
                        {
                            Some((exports, section_table, header_copy, export_dir))=>(exports, section_table,header_copy,export_dir),
                            None=>return,
                        };

                        let dll_basename = String::from(dll_path
                            .file_name().unwrap().to_str().unwrap_or(""));
                        //let _pdbdir = get_guid(&dll_path);
                        //let _guid = _pdbdir.guid;
                        //let _pdb_name = _pdbdir.path;
                        symbols32.push(Symbol
                        {
                            name: dll_basename.to_lowercase(),
                            exports: dll_exports,
                            virtual_address: 0,
                            is_imported: false,
                            header_b64: header_copy,
                            header: Vec::new(),
                            export_dir: export_dir,
                        })
                    }
                },
                _=>{},
            }
        }
        //create json
        if symbols32.len() > 0
        {
            let symbols_output = config_map.x86.pe_file.function_symbol32;
            let symbols = serde_json::to_string_pretty(&symbols32).unwrap();
            let mut file = File::create(symbols_output)
                .expect("error: Could not create symbols json file");
            let _result = file.write_all(symbols.as_bytes());
        }
    }
    else {
        println!("error: Dll folder does not exist.");
    }

    if dll64.exists()
    {

        println!("Getting 64bit symbols.");
        let mut symbols64: Vec<Symbol> = Vec::new();
        let paths = fs::read_dir(dll64).expect("error: dll folder64 is empty");
        for path in paths
        {
            // TODO handle unwrap
            let dll_path = path.unwrap().path();
            match dll_path.extension()
            {
                Some(ref extension)=>{
                    if *extension == "dll"
                    {
                        let (dll_exports, _section_table, header_copy, export_dir) = match extract_exports(&dll_path)
                        {
                            Some((exports, section_table, header_copy, export_dir))=>(exports, section_table,header_copy,export_dir),
                            None=>return,
                        };

                        let dll_basename = String::from(dll_path
                            .file_name().unwrap().to_str().unwrap_or(""));
                        //let _pdbdir = get_guid(&dll_path);
                        //let _guid = _pdbdir.guid;
                        //let _pdb_name = _pdbdir.path;
                        symbols64.push(Symbol
                        {
                            name: dll_basename.to_lowercase(),
                            exports: dll_exports,
                            virtual_address: 0,
                            is_imported: false,
                            header_b64: header_copy,
                            header: Vec::new(),
                            export_dir: export_dir,
                        })
                    }
                },
                _=>{},
            }
        }

        //create json
        if symbols64.len() > 0
        {
            let symbols_output = config_map.x86.pe_file.function_symbol64;
            let symbols = serde_json::to_string_pretty(&symbols64).unwrap();
            let mut file = File::create(symbols_output)
                .expect("error: Could not create symbols json file");
            let _result = file.write_all(symbols.as_bytes());
        }
    }
    else {
        println!("error: Dll folder does not exist.");
    }
}
