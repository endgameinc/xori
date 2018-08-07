pub extern crate serde;
pub extern crate serde_json;
use nom::{IResult, InputLength, le_u64, le_u32, le_u16, le_u8};
//use nom::HexDisplay;
pub use disasm::*;
//use analysis::analyze::Header;

type ULONGLONG = u64;
type DWORD = u32;
type WORD = u16;
type BYTE = u8;

#[derive(Clone,Copy,Debug,Serialize,Deserialize)]
pub struct ImageData {
    pub virtual_address: u32,
    pub size: u32
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ImportLookupTable32 {
    pub elements: Vec<u32>,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ImportLookupTable64 {
    pub elements: Vec<u64>,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ImportAddressTable32 {
    pub elements: Vec<u32>,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ImportAddressTable64 {
    pub elements: Vec<u64>,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ImageImportByName {
    pub hint: u16,
    pub name: String,
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct ImportDllName {
    pub name: String,
}

pub fn import_dll_name(input:&[u8]) -> IResult<&[u8], ImportDllName> {
  do_parse!(input,
    name: take_until!("\0") >>
   ( ImportDllName {
    name:String::from_utf8(name.to_vec()).unwrap_or(String::new()),
   })
  )
}
// TODO: need to better handle unwrap
pub fn image_import_by_name(input:&[u8]) -> IResult<&[u8], ImageImportByName> {
  //println!("image_import_raw:\n{}", &input[0..16].to_hex(16));
  do_parse!(input,
    hint: le_u16 >>
    name: take_until!("\0") >>
   ( ImageImportByName {
    hint,
    name:String::from_utf8(name.to_vec()).unwrap_or(String::new()),
   })
  )
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32, // aka Import Lookup Table RVA aka Characteristics
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,  // aka Import Address Table RVA
}

pub fn import_table(input:&[u8]) -> IResult<&[u8], ImportTable> {
    do_parse!(input,
              // I need to find a better way of specifying a null struct as a tag which is what
              // this is here
        image_import_descriptors: many_till!(image_import_descriptor, tag!(b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")) >>
        ( ImportTable {
            image_import_descriptors: image_import_descriptors.0
        }
        )
        )
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ImageExportDescriptor {
    pub characteristics: u32, //This field appears to be unused and is always set to 0.
    pub time_date_stamp: u32, //The time/date stamp indicating when this file was created.
    pub major_version: u16,
    pub minor_version: u16, //These fields appear to be unused and are set to 0.
    pub name: u32, //The RVA of an ASCIIZ string with the name of this DLL.
    pub base: u32, //The starting ordinal number for exported functions. For example, if the file exports functions with ordinal values of 10, 11, and 12, this field contains 10. To obtain the exported ordinal for a function, you need to add this value to the appropriate element of the AddressOfNameOrdinals array.
    pub number_of_functions: u32, //The number of elements in the AddressOfFunctions array. This value is also the number of functions exported by this module. Theoretically, this value could be different than the NumberOfNames field (next), but actually they're always the same.
    pub number_of_names: u32, //The number of elements in the AddressOfNames array. This value seems always to be identical to the NumberOfFunctions field, and so is the number of exported functions.
    pub address_of_functions: u32, //This field is an RVA and points to an array of function addresses. The function addresses are the entry points (RVAs) for each exported function in this module.
    pub address_of_names: u32, //This field is an RVA and points to an array of string pointers. The strings are the names of the exported functions in this module.
    pub address_of_name_ordinals: u32, //This field is an RVA and points to an array of WORDs. The WORDs are the export ordinals of all the exported functions in this module. However, don't forget to add in the starting ordinal number specified in the Base field.
}

pub fn export_table_entry(input:&[u8], count: usize) -> IResult<&[u8], Vec<u32>> {
    do_parse!(input,
              // I need to find a better way of specifying a null struct as a tag which is what
              // this is here
        image_export_descriptors: count!(le_u32, count) >>
        (image_export_descriptors)
        )
}

pub fn export_table_ord(input:&[u8], count: usize) -> IResult<&[u8], Vec<u16>> {
    do_parse!(input,
              // I need to find a better way of specifying a null struct as a tag which is what
              // this is here
        image_export_descriptors: count!(le_u16, count) >>
        (image_export_descriptors)
        )
}

pub fn image_export_descriptor(input:&[u8]) -> IResult<&[u8], ImageExportDescriptor> {
  do_parse!(input,
    characteristics: le_u32 >>
    time_date_stamp: le_u32 >>
    major_version: le_u16 >>
    minor_version: le_u16 >> 
    name: le_u32 >> 
    base: le_u32 >>
    number_of_functions: le_u32 >> 
    number_of_names: le_u32 >>
    address_of_functions: le_u32 >>
    address_of_names: le_u32 >>
    address_of_name_ordinals: le_u32 >>
    ( ImageExportDescriptor {
        characteristics,
        time_date_stamp,
        major_version,
        minor_version,
        name,
        base,
        number_of_functions,
        number_of_names,
        address_of_functions,
        address_of_names,
        address_of_name_ordinals,
   })
  )
}

pub fn image_import_descriptor(input:&[u8]) -> IResult<&[u8], ImageImportDescriptor> {
  do_parse!(input,
    original_first_thunk: le_u32 >>
    time_date_stamp: le_u32 >>
    forwarder_chain: le_u32 >>
    name: le_u32 >>
    first_thunk: le_u32 >>
   ( ImageImportDescriptor {
    original_first_thunk,
    time_date_stamp,
    forwarder_chain,
    name,
    first_thunk,
   })
  )
}

pub enum ImageDataIndex {
    ExportTable,
    ImportTable,
    ResourceTable,
    ExceptionTable,
    CertificateTable,
    BaseRelocationTable,
    Debug,
    Architecture,
    GlobalPtr,
    TlsTable,
    LoadConfigTable,
    BoundImport,
    ImportAddressTable,
    DelayImportDescriptor,
    ClrRuntimeHeader,
    Reserved,
}


#[derive(Debug,Serialize,Deserialize)]
pub struct ImportTable {
    pub image_import_descriptors: Vec<ImageImportDescriptor>,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ExportTable {
    pub image_export_descriptors: Vec<ImageExportDescriptor>,
}

#[allow(dead_code)]
#[derive(Copy,Clone,Debug,Serialize,Deserialize)]
pub struct ImageOptionalHeader {
    pub magic: WORD,
    pub major_linker_version: BYTE,
    pub minor_linker_version: BYTE,
    pub size_of_code: DWORD,
    pub size_of_initialized_data: DWORD,
    pub size_of_uninitialized_data: DWORD,
    pub address_of_entry_point: DWORD,
    pub base_of_code: DWORD,
    pub base_of_data: DWORD,
    pub image_base: DWORD,
    pub section_alignment: DWORD,
    pub file_alignment: DWORD,
    pub major_operating_system_version: WORD,
    pub minor_operating_system_version: WORD,
    pub major_image_version: WORD,
    pub minor_image_version: WORD,
    pub major_subsystem_version: WORD,
    pub minor_subsystem_version: WORD,
    pub win32_version_value: DWORD,
    pub size_of_image: DWORD,
    pub size_of_headers: DWORD,
    pub check_sum: DWORD,
    pub subsystem: WORD,
    pub dll_characteristics: WORD,
    pub size_of_stack_reserve: DWORD,
    pub size_of_stack_commit: DWORD,
    pub size_of_heap_reserve: DWORD,
    pub size_of_heap_commit: DWORD,
    pub loader_flags: DWORD,
    pub number_of_rva_and_sizes: DWORD,
    pub image_data_directory: [ImageData; 16],
}

#[derive(Debug,Serialize,Deserialize)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

pub fn section_header(input:&[u8]) -> IResult<&[u8], SectionHeader> {
  do_parse!(input,
    name: take!(8) >>
    virtual_size: le_u32 >>
    virtual_address: le_u32 >>
    size_of_raw_data: le_u32 >>
    pointer_to_raw_data: le_u32 >>
    pointer_to_relocations: le_u32 >>
    pointer_to_linenumbers: le_u32 >>
    number_of_relocations: le_u16 >>
    number_of_linenumbers: le_u16 >>
    characteristics: le_u32 >>
   ( SectionHeader {
       name: String::from_utf8(name.to_vec()).unwrap_or(String::new()).trim_matches('\0').to_string(),
       virtual_size,
       virtual_address,
       size_of_raw_data,
       pointer_to_raw_data,
       pointer_to_relocations,
       pointer_to_linenumbers,
       number_of_relocations,
       number_of_linenumbers,
       characteristics,
   })
  )
}

#[derive(Debug,Serialize,Deserialize)]
pub struct SectionTable {
    pub section_headers: Vec<SectionHeader>,
}

#[derive(Copy,Clone,Debug,Serialize,Deserialize)]
pub struct CoffHeader {
    pub signature: u32,
    pub machine: u16,
    pub num_sections: u16,
    pub time_date_stamp: u32,
    pub ptr_to_symbol_table: u32,
    pub num_of_symbol_table: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[derive(Copy,Clone,Debug,Serialize,Deserialize)]
pub struct ImageOptionalHeader64 {
    pub magic: WORD,
    pub major_linker_version: BYTE,
    pub minor_linker_version: BYTE,
    pub size_of_code: DWORD,
    pub size_of_initialized_data: DWORD,
    pub size_of_uninitialized_data: DWORD,
    pub address_of_entry_point: DWORD,
    pub base_of_code: DWORD,
    pub image_base: ULONGLONG,
    pub section_alignment: DWORD,
    pub file_alignment: DWORD,
    pub major_operating_system_version: WORD,
    pub minor_operating_system_version: WORD,
    pub major_image_version: WORD,
    pub minor_image_version: WORD,
    pub major_subsystem_version: WORD,
    pub minor_subsystem_version: WORD,
    pub win32_version_value: DWORD,
    pub size_of_image: DWORD,
    pub size_of_headers: DWORD,
    pub check_sum: DWORD,
    pub subsystem: WORD,
    pub dll_characteristics: WORD,
    pub size_of_stack_reserve: ULONGLONG,
    pub size_of_stack_commit: ULONGLONG,
    pub size_of_heap_reserve: ULONGLONG,
    pub size_of_heap_commit: ULONGLONG,
    pub loader_flags: DWORD,
    pub number_of_rva_and_sizes: DWORD,
    pub image_data_directory: [ImageData; 16],
}

#[derive(Debug,Serialize,Deserialize)]
pub struct DosHeader {
    pub bytes_in_last_block: u16,
    pub blocks_in_file: u16,
    pub num_relocs: u16,
    pub header_paragraphs: u16,
    pub min_extra_paragraphs: u16,
    pub max_extra_paragraphs: u16,
    pub ss: u16,
    pub sp: u16,
    pub checksum: u16,
    pub ip: u16,
    pub cs: u16,
    pub reloc_table_offset: u16,
    pub overlay_number: u16,
    pub e_res: Vec<u8>, // Reserved words
    pub e_oemid: u16, // OEM identifier (for e_oeminfo)
    pub e_oeminfo: u16, // OEM information; e_oemid specific
    pub e_res2: Vec<u8>, // Reserved words
    pub e_lfanew: u32 // File address of the new exe header
}

#[derive(Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct DosStub {
    pub dos_stub: Vec<u8>,
}

#[derive(Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct RichHeader {
    pub rich_header: Vec<u8>,
}

#[derive(Debug,PartialEq,Eq,Serialize,Deserialize)]
pub struct DosFile;


pub fn mz_signature(input:&[u8]) -> IResult<&[u8], DosFile> {
  do_parse!(input,
    tag!("MZ")     >>
   ( DosFile )
  )
}

pub fn image_data(input:&[u8]) -> IResult<&[u8], ImageData> {
  do_parse!(input,
    virtual_address: le_u32 >>
    size: le_u32 >>
   ( ImageData { virtual_address, size})
  )
}

pub fn dos_stub(input: &[u8]) -> IResult<&[u8], DosStub> {
    do_parse!(input,
        dos_stub: take!(input.input_len()) >>
        (DosStub {dos_stub: dos_stub.to_vec()})
        )
}

pub fn rich_header(input: &[u8]) -> IResult<&[u8], RichHeader> {
    do_parse!(input,
        rich_header: take!(input.input_len()) >>
        (RichHeader {rich_header: rich_header.to_vec()})
        )
}

pub fn dos_header(input: &[u8]) -> IResult<&[u8], DosHeader> {
    //let a: [u8; 8] = Default::default();
    do_parse!(
        input,
        mz_signature >>
        bytes_in_last_block: le_u16 >>
        blocks_in_file: le_u16 >>
        num_relocs: le_u16 >>
        header_paragraphs: le_u16 >>
        min_extra_paragraphs: le_u16 >>
        max_extra_paragraphs: le_u16 >>
        ss: le_u16 >>
        sp: le_u16 >>
        checksum: le_u16 >>
        ip: le_u16 >>
        cs: le_u16 >>
        reloc_table_offset: le_u16 >>
        overlay_number: le_u16 >>
        e_res: take!(8) >>
        e_oemid: le_u16 >>
        e_oeminfo: le_u16 >>
        e_res2: take!(20) >>
        e_lfanew: le_u32 >>
        (
            DosHeader {
            bytes_in_last_block: bytes_in_last_block,
            blocks_in_file: blocks_in_file,
            num_relocs: num_relocs,
            header_paragraphs: header_paragraphs,
            min_extra_paragraphs: min_extra_paragraphs,
            max_extra_paragraphs: max_extra_paragraphs,
            ss: ss,
            sp: sp,
            checksum: checksum,
            ip: ip,
            cs: cs,
            reloc_table_offset: reloc_table_offset,
            overlay_number: overlay_number,
            e_res: e_res.to_vec(),
            e_oemid: e_oemid,
            e_oeminfo: e_oeminfo,
            e_res2: e_res2.to_vec(),
            e_lfanew: e_lfanew,
        })
    )
}

#[derive(Copy,Clone,Debug,Serialize,Deserialize)]
pub enum ImageOptionalHeaderKind {
    Pe32(ImageOptionalHeader),
    Pe32Plus(ImageOptionalHeader64),
}

#[derive(Copy,Clone,Debug,Serialize,Deserialize)]
pub struct PeHeader {
    pub coff_header: CoffHeader,
    pub image_optional_header: ImageOptionalHeaderKind
}

pub fn coff_header(input:&[u8]) -> IResult<&[u8], CoffHeader> {
  do_parse!(input,
    signature: le_u32 >>
    machine: le_u16 >>
    num_sections: le_u16 >>
    time_date_stamp: le_u32 >>
    ptr_to_symbol_table: le_u32 >>
    num_of_symbol_table: le_u32 >>
    size_of_optional_header: le_u16 >>
    characteristics: le_u16 >>
   ( CoffHeader {
    signature: signature,
    machine: machine,
    num_sections: num_sections,
    time_date_stamp: time_date_stamp,
    ptr_to_symbol_table: ptr_to_symbol_table,
    num_of_symbol_table: num_of_symbol_table,
    size_of_optional_header: size_of_optional_header,
    characteristics: characteristics,
   })
  )
}

pub fn image_optional_header64(input:&[u8]) -> IResult<&[u8], ImageOptionalHeaderKind> {
  do_parse!(input,
        major_linker_version: le_u8 >>
        minor_linker_version: le_u8 >>
        size_of_code: le_u32 >>
        size_of_initialized_data: le_u32 >>
        size_of_uninitialized_data: le_u32 >>
        address_of_entry_point: le_u32 >>
        base_of_code: le_u32 >>
        image_base: le_u64 >>
        section_alignment: le_u32 >>
        file_alignment: le_u32 >>
        major_operating_system_version: le_u16 >>
        minor_operating_system_version: le_u16 >>
        major_image_version: le_u16 >>
        minor_image_version: le_u16 >>
        major_subsystem_version: le_u16 >>
        minor_subsystem_version: le_u16 >>
        win32_version_value: le_u32 >>
        size_of_image: le_u32 >>
        size_of_headers: le_u32 >>
        check_sum: le_u32 >>
        subsystem: le_u16 >>
        dll_characteristics: le_u16 >>
        size_of_stack_reserve: le_u64 >>
        size_of_stack_commit: le_u64 >>
        size_of_heap_reserve: le_u64 >>
        size_of_heap_commit: le_u64 >>
        loader_flags: le_u32 >>
        number_of_rva_and_sizes: le_u32 >>
        image_data_directory: count_fixed!(ImageData, image_data, 16) >>
        ( ImageOptionalHeaderKind::Pe32Plus(ImageOptionalHeader64 {
        magic: 0x20B,
        major_linker_version: major_linker_version,
        minor_linker_version: minor_linker_version,
        size_of_code: size_of_code,
        size_of_initialized_data: size_of_initialized_data,
        size_of_uninitialized_data: size_of_uninitialized_data,
        address_of_entry_point: address_of_entry_point,
        base_of_code: base_of_code,
        image_base: image_base,
        section_alignment: section_alignment,
        file_alignment: file_alignment,
        major_operating_system_version: major_operating_system_version,
        minor_operating_system_version: minor_operating_system_version,
        major_image_version: major_image_version,
        minor_image_version: minor_image_version,
        major_subsystem_version: major_subsystem_version,
        minor_subsystem_version: minor_subsystem_version,
        win32_version_value: win32_version_value,
        size_of_image: size_of_image,
        size_of_headers: size_of_headers,
        check_sum: check_sum,
        subsystem: subsystem,
        dll_characteristics: dll_characteristics,
        size_of_stack_reserve: size_of_stack_reserve,
        size_of_stack_commit: size_of_stack_commit,
        size_of_heap_reserve: size_of_heap_reserve,
        size_of_heap_commit: size_of_heap_commit,
        loader_flags: loader_flags,
        number_of_rva_and_sizes: number_of_rva_and_sizes,
        image_data_directory
        }))
  )
}

pub fn image_optional_header(input:&[u8]) -> IResult<&[u8], ImageOptionalHeaderKind> {
  do_parse!(input,
        major_linker_version: le_u8 >>
        minor_linker_version: le_u8 >>
        size_of_code: le_u32 >>
        size_of_initialized_data: le_u32 >>
        size_of_uninitialized_data: le_u32 >>
        address_of_entry_point: le_u32 >>
        base_of_code: le_u32 >>
        base_of_data: le_u32 >>
        image_base: le_u32 >>
        section_alignment: le_u32 >>
        file_alignment: le_u32 >>
        major_operating_system_version: le_u16 >>
        minor_operating_system_version: le_u16 >>
        major_image_version: le_u16 >>
        minor_image_version: le_u16 >>
        major_subsystem_version: le_u16 >>
        minor_subsystem_version: le_u16 >>
        win32_version_value: le_u32 >>
        size_of_image: le_u32 >>
        size_of_headers: le_u32 >>
        check_sum: le_u32 >>
        subsystem: le_u16 >>
        dll_characteristics: le_u16 >>
        size_of_stack_reserve: le_u32 >>
        size_of_stack_commit: le_u32 >>
        size_of_heap_reserve: le_u32 >>
        size_of_heap_commit: le_u32 >>
        loader_flags: le_u32 >>
        number_of_rva_and_sizes: le_u32 >>
        image_data_directory: count_fixed!(ImageData, image_data, 16) >>
        (  ImageOptionalHeaderKind::Pe32(ImageOptionalHeader {
        magic: 0x10B,
        major_linker_version: major_linker_version,
        minor_linker_version: minor_linker_version,
        size_of_code: size_of_code,
        size_of_initialized_data: size_of_initialized_data,
        size_of_uninitialized_data: size_of_uninitialized_data,
        address_of_entry_point: address_of_entry_point,
        base_of_code: base_of_code,
        base_of_data: base_of_data,
        image_base: image_base,
        section_alignment: section_alignment,
        file_alignment: file_alignment,
        major_operating_system_version: major_operating_system_version,
        minor_operating_system_version: minor_operating_system_version,
        major_image_version: major_image_version,
        minor_image_version: minor_image_version,
        major_subsystem_version: major_subsystem_version,
        minor_subsystem_version: minor_subsystem_version,
        win32_version_value: win32_version_value,
        size_of_image: size_of_image,
        size_of_headers: size_of_headers,
        check_sum: check_sum,
        subsystem: subsystem,
        dll_characteristics: dll_characteristics,
        size_of_stack_reserve: size_of_stack_reserve,
        size_of_stack_commit: size_of_stack_commit,
        size_of_heap_reserve: size_of_heap_reserve,
        size_of_heap_commit: size_of_heap_commit,
        loader_flags: loader_flags,
        number_of_rva_and_sizes: number_of_rva_and_sizes,
        image_data_directory
        }) 
            )
  )
}

pub fn pe_header(input: &[u8]) -> IResult<&[u8], PeHeader> {
    do_parse!(input,
        coff_header: coff_header >>
        optional_header: switch!(le_u16, 0x10B => call!(image_optional_header) | 0x20B => call!(image_optional_header64)) >>
        (PeHeader {
            coff_header:coff_header,
            image_optional_header: optional_header
        }
        )
        )
}

pub fn section_table(input: &[u8], num_sections: u16) -> IResult<&[u8], SectionTable> {
    do_parse!(input,
              section_headers: count!(section_header, num_sections as usize) >>
              (SectionTable {
                  section_headers
              }))
}

pub fn import_address_table32(input: &[u8]) -> IResult<&[u8], ImportAddressTable32> {
    do_parse!(input,
              elements: many_till!(le_u32, tag!(b"\0\0\0\0")) >>
              (ImportAddressTable32 {
                  elements: elements.0 // many_till produces a tuple, the second element would be the \0\0\0\0
              })
              )
}

pub fn import_lookup_table32(input: &[u8]) -> IResult<&[u8], ImportLookupTable32> {
    do_parse!(input,
              elements: many_till!(le_u32, tag!(b"\0\0\0\0")) >>
              (ImportLookupTable32 {
                  elements: elements.0 // many_till produces a tuple, the second element would be the \0\0\0\0
              })
              )
}

pub fn import_address_table64(input: &[u8]) -> IResult<&[u8], ImportAddressTable64> {
    do_parse!(input,
              elements: many_till!(le_u64, tag!(b"\0\0\0\0\0\0\0\0")) >>
              (ImportAddressTable64 {
                  elements: elements.0 // many_till produces a tuple, the second element would be the \0\0\0\0\0\0\0\0
              })
              )
}

pub fn import_lookup_table64(input: &[u8]) -> IResult<&[u8], ImportLookupTable64> {
    do_parse!(input,
              elements: many_till!(le_u64, tag!(b"\0\0\0\0\0\0\0\0")) >>
              (ImportLookupTable64 {
                  elements: elements.0 // many_till produces a tuple, the second element would be the \0\0\0\0\0\0\0\0
              })
              )
}

pub fn rva_to_file_offset(rva: usize, section_table: &SectionTable) -> usize {
    // check to see if rva happens to not be in a section
    if rva < *&section_table.section_headers[0].pointer_to_raw_data as usize {
        return rva;
    }
    // iterate over the sections and use the section virtual address and pointer to raw data to get
    // the offset
    for section in &section_table.section_headers {
        if rva >= section.virtual_address as usize && rva < (section.virtual_address as usize + section.size_of_raw_data as usize) {
            return rva - section.virtual_address as usize + section.pointer_to_raw_data as usize;
        }
    }
    return 0;
}
