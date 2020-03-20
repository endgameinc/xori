#![allow(unused)]

extern crate memmap;
use memmap::Mmap;
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
extern crate nom;
extern crate xori;
use xori::analysis::formats::pe::{dos_header, dos_stub, image_import_by_name,
                                  image_import_descriptor, import_dll_name, import_table,
                                  pe_header, rich_header, rva_to_file_offset, section_table,
                                  ImageDataIndex, ImageOptionalHeaderKind, import_address_table32,
                                  import_address_table64, import_lookup_table32,
                                  import_lookup_table64};
use nom::{HexDisplay, IResult, InputLength, Needed, Offset};
use nom::error::ErrorKind;
use nom::number::complete::{be_u8, le_u64, le_u32, le_u16, le_u8};
extern crate serde;
extern crate serde_json;

fn main() {
    fn foo() -> std::io::Result<()> {
        let path = env::args()
            .nth(1)
            .expect("supply a single path as the program argument");
        let file = File::open(path).expect("failed to open the file");
        let mmap = unsafe { Mmap::map(&file).expect("failed to map the file") };
        let res = dos_header(&mmap);
        let peh;
        let pe_offset;
        //let end_of_dos_header;
        match res {
            Ok((i, o)) => {
                pe_offset = o.e_lfanew as usize;
                let serialized = serde_json::to_string(&o).unwrap();
                println!("serialized = {}", serialized);
                let dos_stub = dos_stub(&mmap[mmap.offset(i)..(mmap.offset(i) + 64)]);
                let rich_header = rich_header(&mmap[mmap.offset(i) + 64..pe_offset]);
                match dos_stub {
                    Ok((i, o)) => {
                        let serialized = serde_json::to_string(&o).unwrap();
                        println!("dos stub = {}", serialized);
                    }
                    _ => {
                        println!("error or incomplete");
                        panic!("cannot parse header");
                    }
                }
                match rich_header {
                    Ok((i, o)) => {
                        let serialized = serde_json::to_string(&o).unwrap();
                        println!("rich_header = {}", serialized);
                    }
                    _ => {
                        println!("error or incomplete");
                        panic!("cannot parse header");
                    }
                }
            }
            _ => {
                println!("error or incomplete");
                panic!("cannot parse header");
            }
        }
        let res2 = pe_header(&mmap[pe_offset..]);
        let idd_rva;
        let idd_size;
        let ep;
        let num_rvas;
        let ib: u64;
        let leftover;
        let bits: u8;
        match res2 {
            Ok((i, o)) => {
                let serialized = serde_json::to_string(&o).unwrap();
                peh = o;
                println!("serialized = {}", serialized);
                match o.image_optional_header {
                    ImageOptionalHeaderKind::Pe32(ioh) => {
                        println!(
                            "entry_point: {:#X}\nimage_base: {:#X}\nImport Table Address: {:#X}",
                            ioh.address_of_entry_point,
                            ioh.image_base,
                            ioh.image_data_directory[ImageDataIndex::ImportTable as usize]
                                .virtual_address
                        );
                        idd_rva = ioh.image_data_directory[ImageDataIndex::ImportTable as usize]
                            .virtual_address;
                        idd_size =
                            ioh.image_data_directory[ImageDataIndex::ImportTable as usize].size;
                        num_rvas = ioh.number_of_rva_and_sizes;
                        ep = ioh.address_of_entry_point;
                        ib = ioh.image_base.into();
                        bits = 32;
                    }
                    ImageOptionalHeaderKind::Pe32Plus(ioh) => {
                        println!(
                            "entry_point: {:#X}\nimage_base: {:#X}\nImport Table Address: {:#X}",
                            ioh.address_of_entry_point,
                            ioh.image_base,
                            ioh.image_data_directory[ImageDataIndex::ImportTable as usize]
                                .virtual_address
                        );
                        idd_rva = ioh.image_data_directory[ImageDataIndex::ImportTable as usize]
                            .virtual_address;
                        idd_size =
                            ioh.image_data_directory[ImageDataIndex::ImportTable as usize].size;
                        num_rvas = ioh.number_of_rva_and_sizes;
                        ep = ioh.address_of_entry_point;
                        ib = ioh.image_base;
                        bits = 64;
                    }
                }
                leftover = i;
            }
            _ => {
                println!("error or incomplete");
                panic!("cannot parse header");
            }
        }
        println!("num_rvas: {}", num_rvas);
        println!("idd_rva: {:#X}", idd_rva);
        println!("idd_size: {}", idd_size);
        let res3 = section_table(leftover, peh.coff_header.num_sections);
        let section_table;
        match res3 {
            Ok((i, o)) => {
                println!("parsed: {:?}", o);
                section_table = o;
                let res3 =
                    import_table(&mmap[rva_to_file_offset(idd_rva as usize, &section_table)..]);
                match res3 {
                    Ok((i, o)) => {
                        println!("parsed: {:?}", o);
                        for import_descriptor in o.image_import_descriptors {
                          
                            let dllname = import_dll_name(
                                &mmap[rva_to_file_offset(
                                    import_descriptor.name as usize,
                                    &section_table,
                                )..],
                            ).unwrap();
                            // if 32 bit
                            match bits {
                                32 => {
                                    let res4 = import_lookup_table32(
                                        &mmap[rva_to_file_offset(
                                            import_descriptor.original_first_thunk as usize,
                                            &section_table,
                                        )..],
                                    );
                                    match res4 {
                                        Ok((i, o)) => {
                                           
                                            println!(
                                                "boop: {:#X}",
                                                rva_to_file_offset(
                                                    import_descriptor.original_first_thunk as usize,
                                                    &section_table
                                                )
                                            );
                                            println!("the 32-bit ILT");
                                            println!("********* {}", o.elements.len());
                                            for (off, addr) in o.elements.iter().enumerate() {
                                                if *addr & 0x80000000 == 0x0 {
                                                    let bn = image_import_by_name(
                                                        &mmap[rva_to_file_offset(
                                                            *addr as usize,
                                                            &section_table,
                                                        )..],
                                                    );
                                                    match bn {
                                                        Ok((i, o)) => {
                                                            println!("ord {:?} {:?} from {:?} at offset {:#X} addr {:#X} from ILT {:#X}", off+1, o.name, dllname.1.name, rva_to_file_offset(*addr as usize,&section_table), *addr, rva_to_file_offset(import_descriptor.original_first_thunk as usize,&section_table) + (off * 0x4 ));
                                                        }
                                                        _ => println!("oh"),
                                                    }
                                                } else {
                                                    println!(
                                                        "Ordinal: {:?} from {:?}",
                                                        addr ^ 0x80000000,
                                                        dllname.1.name
                                                    );
                                                }
                                            }
                                        }
                                        _ => {
                                            println!("error or incomplete");
                                            panic!("cannot parse header");
                                        }
                                    }
                                    let res5 = import_address_table32(
                                        &mmap[rva_to_file_offset(
                                            import_descriptor.first_thunk as usize,
                                            &section_table,
                                        )..],
                                    );
                                    match res5 {
                                        Ok((i, o)) => {
                                          
                                            println!("the 32-bit IAT");
                                            for (off, addr) in o.elements.iter().enumerate() {
                                               
                                                if *addr & 0x80000000 == 0x0 {
                                                    let bn = image_import_by_name(
                                                        &mmap[rva_to_file_offset(
                                                            *addr as usize,
                                                            &section_table,
                                                        )..],
                                                    );
                                                    match bn {
                                                        Ok((i, o)) => {
                                                            println!("ord {:?} {:?} from {:?} at offset {:#X} addr {:#X} from IAT {:#X}", off+1, o.name, dllname.1.name, rva_to_file_offset(*addr as usize,&section_table), *addr, rva_to_file_offset(import_descriptor.first_thunk as usize,&section_table) + (off * 0x4 ));
                                                        }
                                                        _ => println!("oh"),
                                                    }
                                                } else {
                                                    println!(
                                                        "Ordinal: {:?} from {:?}",
                                                        addr ^ 0x80000000,
                                                        dllname.1.name
                                                    );
                                                }
                                            }
                                        }
                                        _ => {
                                            println!("error or incomplete");
                                            panic!("cannot parse header");
                                        }
                                    }
                                }
                                64 => {
                                    let res4 = import_lookup_table64(
                                        &mmap[rva_to_file_offset(
                                            import_descriptor.original_first_thunk as usize,
                                            &section_table,
                                        )..],
                                    );
                                    match res4 {
                                        Ok((i, o)) => {
                                            println!("the 64-bit ILT");
                                            for (off, addr) in o.elements.iter().enumerate() {
                                                if *addr & 0x8000000000000000 == 0x0 {
                                                    let bn = image_import_by_name(
                                                        &mmap[rva_to_file_offset(
                                                            *addr as usize,
                                                            &section_table,
                                                        )..],
                                                    );
                                                    match bn {
                                                        Ok((i, o)) => {
                                                            println!("{:?} from {:?} at offset {:#X} addr {:#X} from ILT {:#X}", o.name, dllname.1.name, rva_to_file_offset(*addr as usize,&section_table), *addr, rva_to_file_offset(import_descriptor.original_first_thunk as usize,&section_table) + (off * 0x8 ));
                                                        }
                                                        _ => println!("oh"),
                                                    }
                                                } else {
                                                    println!(
                                                        "Ordinal: {:?} from {:?}",
                                                        addr ^ 0x8000000000000000,
                                                        dllname.1.name
                                                    );
                                                }
                                            }
                                        }
                                        _ => {
                                            println!("error or incomplete");
                                            panic!("cannot parse header");
                                        }
                                    }
                                    let res5 = import_address_table64(
                                        &mmap[rva_to_file_offset(
                                            import_descriptor.first_thunk as usize,
                                            &section_table,
                                        )..],
                                    );
                                    match res5 {
                                        Ok((i, o)) => {
                                          
                                            println!("the 64-bit IAT");
                                            for (off, addr) in o.elements.iter().enumerate() {
                                                if *addr & 0x8000000000000000 == 0x0 {
                                                    let bn = image_import_by_name(
                                                        &mmap[rva_to_file_offset(
                                                            *addr as usize,
                                                            &section_table,
                                                        )..],
                                                    );
                                                    match bn {
                                                        Ok((i, o)) => {
                                                            println!("{:?} from {:?} at offset {:#X} addr {:#X} from IAT {:#X}", o.name, dllname.1.name, rva_to_file_offset(*addr as usize,&section_table), *addr, rva_to_file_offset(import_descriptor.first_thunk as usize,&section_table) + (off * 0x8 ));
                                                        }
                                                        _ => println!("oh"),
                                                    }
                                                } else {
                                                    println!(
                                                        "Ordinal: {:?} from {:?}",
                                                        addr ^ 0x8000000000000000,
                                                        dllname.1.name
                                                    );
                                                }
                                            }
                                        }
                                        _ => {
                                            println!("error or incomplete");
                                            panic!("cannot parse header");
                                        }
                                    }
                                }
                                _ => {
                                    println!("oh geez 2");
                                }
                            }
                        }
                    }
                    _ => {
                        println!("error or incomplete");
                        panic!("cannot parse header");
                    }
                }
            }
            _ => {
                println!("derp");
            }
        }

        Ok(())
    }
    foo();
}

