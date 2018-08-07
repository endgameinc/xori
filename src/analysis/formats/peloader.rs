// peloader.rs]
extern crate base64;
use analysis::formats::pe::*;
use configuration::Config;
use analysis::analyze::*;
use arch::x86::analyzex86::*;
use serde_json;
//use serde_json::{Value};
use std::path::Path;
use bincode::serialize;
use encoding::all::UTF_16LE;
use encoding::{Encoding, EncoderTrap};


pub const TEB_ADDRESS_64: u64 = 0x7FFFFFDA000;
pub const TEB_ADDRESS: u64 = 0x7FFDA000;
pub const PEB_ADDRESS_64: u64 = 0x7FFFFFDF000;  
pub const PEB_ADDRESS: u64 = 0x7FFDF000;
pub const DLL_ADDRESS_64: u64 = 0x7FE64D50000;
pub const DLL_ADDRESS: u64 = 0x64D50000;
pub const VIRTUAL_ADDRESS_OFFSET: u64 = 0x100000;

#[derive(Debug, Clone, PartialEq)]
pub enum SectionMask{
    Code=0x00000020, // The section contains executable code
    InitData=0x00000040, // The section contains initialized data
    UnInitData=0x00000080, // The section contains uninitialized data
    MemShared=0x10000000, // The section can be shared in memory
    MemExecute=0x20000000, // The section can be executed as code
    MemRead=0x40000000,  // The section can be read
    MemWrite=0x80000000,  // The section can be written to
}

#[derive(Serialize, Deserialize)]
struct ThreadInformationBlock32
{
    // reference: https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
    seh_frame:                u32,  //0x00
    stack_base:               u32,  //0x04
    stack_limit:              u32,  //0x08
    subsystem_tib:            u32,  //0x0C
    fiber_data:               u32,  //0x10
    arbitrary_data:           u32,  //0x14
    self_addr:                u32,  //0x18
    //End                     of    NT      subsystem independent part
    environment_ptr:          u32,  //0x1C
    process_id:               u32,  //0x20
    thread_id:                u32,  //0x24
    active_rpc_handle:        u32,  //0x28
    tls_addr:                 u32,  //0x2C  thread    local       storage
    peb_addr:                 u32,  //0x30
    last_error:               u32,  //0x34
    critical_section_count:   u32,  //0x38
    csr_client_thread:        u32,  //0x3C
    win32_thread_info:        u32,  //0x40
    win32_client_info:        [u32; 31],    //0x44
    fastsyscall:              u32,  //0xC0
    current_locale:           u32,  //0xC4
    fp_software_status_reg:   u32,  //0xC8
    reserved:                 [u64; 27],    //0xCC
    exception_code:           u32,  //0x1A4
    activation_context_stack: [u8;  20],    //0x1A8
    spare_bytes:              [u8;  24],    //0x1BC
    
    /*
        // Ignoring
        gdi_teb_batch: [u8; 1248], //0x1D4
        gdi_region: u32, //0x6DC
        gdi_pen: u32, //0x6E0
        gdi_brush: u32, //0x6E4
        real_process_id: u32, //0x6E8
        real_thread_id: u32, //0x6EC
        gdi_catched_handle: u32, //0x6F0
        gdi_client_process_id: u32, //0x6F4
        gdi_client_thread_id: u32, //0x6F8
        gdi_thead_locale_info: u32, //0x6FC
        reserved2: [u8; 20], //0x700
        reserved3: [u8; 1248], //0x714
        last_status_value: u32, //0xBF4
        static_unicode_string: [u8; 532], //0xBF8
        deallocation_stack: u32, //0xE0C
        tls_slots: [u8; 256], //0xE10
        tls_links: u64, //0xF10
        vdm: u32, //0xF18
        reserved4: u32, //0xF1C
        thread_error_mode: u32, //0xF28
    */
    
}

#[derive(Serialize, Deserialize)]
struct ThreadInformationBlock64
{
    // reference: https://en.wikipedia.org/wiki/Win32_Thread_Information_Block
    seh_frame:                u64,  //0x00
    stack_base:               u64,  //0x08
    stack_limit:              u64,  //0x10
    subsystem_tib:            u64,  //0x18
    fiber_data:               u64,  //0x20
    arbitrary_data:           u64,  //0x28
    self_addr:                u64,  //0x30
    //End of NT subsystem independent part
    environment_ptr:          u64,  //0x38
    process_id:               u64,  //0x40
    thread_id:                u64,  //0x48
    active_rpc_handle:        u64,  //0x50
    tls_addr:                 u64,  //0x58
    peb_addr:                 u64,  //0x60
    last_error:               u32,  //0x68
    critical_section_count:   u64,  //0x6C
    csr_client_thread:        u64,  //0x70
    win32_thread_info:        u64,  //0x78
    user32_reserved:          [u32; 26],    //0x80
    user_reserved:            [u32; 5],     //0xe8
    fastsyscall:              u64,  //0x100
    current_locale:           u32,  //0x108
    fp_software_status_reg:   u32,  //0x10c
    reserved:                 [u64; 27],    //0x110
    reserved1:                [u64; 27],    //0x110
    exception_code:           i64,  //0x2c0
    activation_context_stack: u64,  //0x2c8
    spare_bytes:              [u8;  24],    //0x2d0
    
    /*
        // Ignoring
        tx_fs_context: u32, //0x2e8
        gdi_teb_batch: [u8; 1248], //0x2f0 
        real_process_id: u64, //0x7d8
        real_thread_id: u64, //0x7e0
        gdi_catched_handle: u64, //0x7e8
        gdi_client_process_id: u32, //0x7f0
        gdi_client_thread_id: u32, //0x7f4
        gdi_thead_locale_info: u64, //0x7f8
        win32_client_info2: [u8; 62], //0x800
        gl_dispatch_table: [u64; 233], //0x9f0
        gl_reserved1: [u8; 29], //0x1138
        gl_reserved2: u64, //0x1220
        gl_section_info: u64, //0x1228
        gl_section: u64, //0x1230
        gl_table: u64, //0x1238
        gl_currentrc: u64, //0x1240
        gl_context: u64, //0x1248
        last_status_value: u64, //0x1250
        static_unicode_string: [u8; 544], //0x1258
        deallocation_stack: u64, //0x1478
        tls_slots: [u8; 512], //0x1480
        tls_links: [u8; 32], //0x1680
        vdm: u64, //0x1690
        reserved2: u64, //0x1698
        dbg_ss_reserved: [u64; 2], //0x16a0
        hard_error_mode: u64, //0x16b0
    */
}

#[derive(Serialize, Deserialize)]
#[repr(C)]
struct ProcessEnvironmentBlock32
{
    inherited_addr_space:                   bool, //0x000
    read_image_fileexec_options:            bool, //0x001
    being_debugged:                         bool, //0x002
    bit_field:                              u8,  //0x003
    mutant:                                 u32,  //0x004
    image_base_address:                     u32,  //0x008
    peb_ldr_data:                           u32,  //0x000C
    process_parameters:                     u32,  //0x0010
    sub_system_data:                        u32,  //0x0014
    process_heap:                           u32,  //0x0018
    fast_peb_lock:                          u32,  //0x001C
    atl_thunk_s_list_ptr:                   u32,  //0x0020
    ifeo_key:                               u32,  //0x0024
    cross_process_flags:                    u32,  //0x0028
    kernel_callback_table:                  u32,  //0x002C
    system_reserved:                        u32,  //0x0030
    atl_thunk_slist_ptr32:                  u32,  //0x0034
    api_set_map:                            u32,  //0x0038
    tls_expansion_counter:                  u32,  //0x003C
    tls_bitmap:                             u32,  //0x0040
    tls_bitmap_bits:                        [u32; 2],      //0x0044
    read_only_shared_memory_base:           u32,  //0x004C
    hotpatch_information:                   u32,  //0x0050
    read_only_static_server_data:           u32,  //0x0054
    ansi_code_page_data:                    u32,  //0x0058
    oem_code_page_data:                     u32,  //0x005C
    unicode_case_table_data:                u32,  //0x0060
    number_of_processors:                   u32,  //0x0064
    nt_global_flag:                         u64,  //0x0068
    critical_section_timeout:               i64,  //0x0070
    heap_segment_reserve:                   u32,  //0x0078
    heap_segment_commit:                    u32,  //0x007C
    heap_de_commit_total_free_threshold:    u32,  //0x0080
    heap_de_commit_free_block_threshold:    u32,  //0x0084
    number_of_heaps:                        u32,  //0x0088
    maximum_number_of_heaps:                u32,  //0x008C
    process_heaps:                          u32,  //0x0090
    gdi_shared_handle_table:                u32,  //0x0094
    process_starter_helper:                 u32,  //0x0098
    gdi_d_c_attribute_list:                 u32,  //0x009C
    loader_lock:                            u32,  //0x00A0
    os_major_version:                       u32,  //0x00A4
    os_minor_version:                       u32,  //0x00A8
    os_build_number:                        u16,  //0x00AC
    os_csd_version:                         u16,  //0x00AE
    os_platform_id:                         u32,  //0x00B0
    image_subsystem:                        u32,  //0x00B4
    image_subsystem_major_version:          u32,  //0x00B8
    image_subsystem_minor_version:          u32,  //0x00BC
    active_process_affinity_mask:           u32,  //0x00C0
    gdi_handle_buffer:                      [u32; 17],   //0x00C4
    gdi_handle_buffer1:                     [u32; 17],   //0x00C4 Hack
    post_process_init_routine:              u32,  //0x014C
    tls_expansion_bitmap:                   u32,  //0x0150
    tls_expansion_bitmap_bits:              [u32; 32],   //0x0154
    session_id:                             u32,  //0x01D4
    app_compat_flags:                       u64,  //0x01D8
    app_compat_flags_user:                  u64,  //0x01E0
    pshim_data:                             u32,  //0x01E8
    app_compat_info:                        u32,  //0x01EC
    csd_version:                            [u8;  8],      //0x01F0
    activation_context_data:                u32,  //0x01F8
    process_assembly_storage_map:           u32,  //0x01FC
    system_default_activation_context_data: u32,  //0x0200
    system_assembly_storage_map:            u32,  //0x0204
    minimum_stack_commit:                   u32,  //0x0208
    fls_callback:                           u32,  //0x020C
    fls_list_head:                          u64,  //0x0210
    fls_bitmap:                             u32,  //0x0218
    fls_bitmap_bits:                        [u32; 4],      //0x021C
    fls_high_index:                         u32,  //0x022C
    wer_registration_data:                  u32,  //0x0230
    wer_ship_assert_ptr:                    u32,  //0x0234
    pcontext_data:                          u32,  //0x0238
    pimage_header_hash:                     u32,  //0x023C
    tracing_flags:                          u32,  //0x0240
}


#[derive(Serialize, Deserialize)]
struct ProcessEnvironmentBlock64
{
    inherited_addr_space:                   bool, //0x000
    read_image_fileexec_options:            bool, //0x001
    being_debugged:                         bool, //0x002
    bit_field:                              [u8; 5],  //0x003
    mutant:                                 u64,  //0x008
    image_base_address:                     u64,  //0x0010
    peb_ldr_data:                           u64,  //0x0018
    process_parameters:                     u64,  //0x0020
    sub_system_data:                        u64,  //0x0028
    process_heap:                           u64,  //0x0030
    fast_peb_lock:                          u64,  //0x0038
    atl_thunk_s_list_ptr:                   u64,  //0x0040
    ifeo_key:                               u64,  //0x0048
    cross_process_flags:                    u64,  //0x0050
    kernel_callback_table:                  u64,  //0x0058
    system_reserved:                        u32,  //0x0060
    atl_thunk_slist_ptr32:                  u32,  //0x0064
    api_set_map:                            u64,  //0x0068
    tls_expansion_counter:                  u64,  //0x0070
    tls_bitmap:                             u64,  //0x0078
    tls_bitmap_bits:                        [u32; 2],      //0x0080
    read_only_shared_memory_base:           u64,  //0x0088
    hotpatch_information:                   u64,  //0x0090
    read_only_static_server_data:           u64,  //0x0098
    ansi_code_page_data:                    u64,  //0x00A0
    oem_code_page_data:                     u64,  //0x00A8
    unicode_case_table_data:                u64,  //0x00B0
    number_of_processors:                   u32,  //0x00B8
    nt_global_flag:                         u32,  //0x00BC
    critical_section_timeout:               i64,  //0x00C0
    heap_segment_reserve:                   u64,  //0x00C8
    heap_segment_commit:                    u64,  //0x00D0
    heap_de_commit_total_free_threshold:    u64,  //0x00D8
    heap_de_commit_free_block_threshold:    u64,  //0x00e0
    number_of_heaps:                        u32,  //0x00e8
    maximum_number_of_heaps:                u32,  //0x00FC
    process_heaps:                          u64,  //0x00F0
    gdi_shared_handle_table:                u64,  //0x00F8
    process_starter_helper:                 u64,  //0x0100
    gdi_d_c_attribute_list:                 u64,  //0x0108
    loader_lock:                            u64,  //0x0110
    os_major_version:                       u32,  //0x0118
    os_minor_version:                       u32,  //0x011C
    os_build_number:                        u16,  //0x0120
    os_csd_version:                         u16,  //0x0122
    os_platform_id:                         u32,  //0x0124
    image_subsystem:                        u32,  //0x0128
    image_subsystem_major_version:          u32,  //0x012C
    image_subsystem_minor_version:          u64,  //0x0130
    active_process_affinity_mask:           u64,  //0x0138
    gdi_handle_buffer:                      [u64; 30], //0x140 Hack
    post_process_init_routine:              u64,  //0x230
    tls_expansion_bitmap:                   u64,  //0x238
    tls_expansion_bitmap_bits:              [u32; 32], //0x240
    session_id:                             u64,  //0x2C0
    app_compat_flags:                       u64,  //0x2C8
    app_compat_flags_user:                  u64,  //0x2D0
    pshim_data:                             u64,  //0x2D8
    app_compat_info:                        u64,  //0x2E0
    csd_version:                            [u8;  16], //0x2E8
    activation_context_data:                u64,  //0x2F8
    process_assembly_storage_map:           u64,  //0x300
    system_default_activation_context_data: u64,  //0x308
    system_assembly_storage_map:            u64,  //0x310
    minimum_stack_commit:                   u64,  //0x318
    fls_callback:                           u64,  //0x320
    fls_list_head:                          u64,  //0x328
    fls_bitmap:                             u64,  //0x330
    fls_bitmap_bits:                        [u64; 3], //0x338
    fls_high_index:                         u64,  //0x350
    wer_registration_data:                  u64,  //0x358
    wer_ship_assert_ptr:                    u64,  //0x360
    pcontext_data:                          u64,  //0x368
    pimage_header_hash:                     u64,  //0x370
    tracing_flags:                          u64,  //0x378
}

#[derive(Serialize, Deserialize)]
struct PebLoaderData32
{
    // Size of structure, used by ntdll.dll as structure version ID
    length: u32, //0x00 
    // If set, loader data section for current process is initialized
    initialized: [u8; 4], //0x04
    ss_handle: u32, //0x08
    // Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in load order
    in_load_order_module_list: [u32; 2], //0x0C
    // Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in memory placement order
    in_memory_order_module_list: [u32; 2], //0x14
    // Pointer to LDR_DATA_TABLE_ENTRY structure. Previous and next module in initialization order
    in_initialization_order_module_list: [u32; 2], //0x1C
    entry_in_progress: u32, //0x24
    shutdown_in_progress: u32, //0x28
    shutdown_thread_id: u32, //0x2C
}
#[derive(Serialize, Deserialize)]
struct PebLoaderData64
{
    length: u32, //0x00
    initialized: [u8; 4], //0x04
    ss_handle: u64, //0x08
    in_load_order_module_list: [u64; 2], //0x10
    in_memory_order_module_list: [u64; 2], //0x20
    in_initialization_order_module_list: [u64; 2], //0x30
    entry_in_progress: u64, //0x40
    shutdown_in_progress: u64, //0x48
    shutdown_thread_id: u64, //0x50
}

#[derive(Debug,Serialize, Deserialize)]
struct WinUnicodeSting32 
{
  length: u16,
  maximum_length: u16,
  buffer: u32,
}
#[derive(Debug,Serialize, Deserialize)]
struct WinUnicodeSting64 
{
  length: u32,
  maximum_length: u32,
  buffer: u64,
}
#[derive(Debug, Serialize, Deserialize)]
struct PebLdrTableEntry32
{
    in_load_order_links:           [u32;              2], //0x00
    in_memory_order_links:         [u32;              2], //0x08
    in_initialization_order_links: [u32;              2], //0x10
    dll_base:                      u32,               //0x18
    entry_point:                   u32,               //0x1C
    size_of_image:                 u32,               //0x20
    full_dll_name:                 WinUnicodeSting32, //0x24
    base_dll_name:                 WinUnicodeSting32, //0x2C
    flags:                         u32,               //0x34
    load_count:                    u16,               //0x38
    tls_index:                     u16,               //0x3A
    hash_links:                    [u32;              2], //0x3C
}
#[derive(Debug, Serialize, Deserialize)]
struct PebLdrTableEntry64
{
    in_load_order_links:           [u64;              2], //0x00
    in_memory_order_links:         [u64;              2], //0x10
    in_initialization_order_links: [u64;              2], //0x20
    dll_base:                      u64,               //0x30
    entry_point:                   u64,               //0x38
    size_of_image:                 u64,               //0x40
    full_dll_name:                 WinUnicodeSting64, //0x48
    base_dll_name:                 WinUnicodeSting64, //0x58
    flags:                         u32,               //0x68
    load_count:                    u16,               //0x6C
    tls_index:                     u16,               //0x6E
    hash_links:                    [u64;              2], //0x70
}

#[derive(Debug,Clone,Serialize)]
pub struct Import
{
    pub name: String,
    pub virtual_address: u64,
    pub import_address_list: Vec<ImportAddressValue>,
    pub is_symbols: bool,
}

#[derive(Debug,Clone,Serialize)]
pub struct Section
{
    pub name: String,
    pub virtual_size: u64,
    pub virtual_address: u64,
    pub size_of_raw_data: u64,
    pub pointer_to_raw_data: u64,
    pub characteristics: u32,
}

impl Section {
    pub fn is_execute(&self)->bool
    {
        if (self.characteristics & SectionMask::MemExecute as u32) == SectionMask::MemExecute as u32
        {
            return true;
        }
        return false;
    }
    pub fn is_write(&self)->bool
    {
        if (self.characteristics & SectionMask::MemWrite as u32) == SectionMask::MemWrite as u32
        {
            return true;
        }
        return false;
    } 
    pub fn is_read(&self)->bool
    {
        if (self.characteristics & SectionMask::MemRead as u32) == SectionMask::MemRead as u32
        {
            return true;
        }
        return false;
    }
    pub fn is_code(&self)->bool
    {
        if (self.characteristics & SectionMask::Code as u32) == SectionMask::Code as u32
        {
            return true;
        }
        return false;
    }
    pub fn is_init_data(&self)->bool
    {
        if (self.characteristics & SectionMask::InitData as u32) == SectionMask::InitData as u32
        {
            return true;
        }
        return false;
    }
    pub fn is_uninit_data(&self)->bool
    {
        if (self.characteristics & SectionMask::UnInitData as u32) == SectionMask::UnInitData as u32
        {
            return true;
        }
        return false;
    }      
}

fn load_symbol(
    symbols_path: &String) -> Option<Vec<Symbol>>
{
    debug!("Loading Symbols");
    let path = Path::new(symbols_path);
    if !path.exists(){
        debug!("error: symbols file does not exist");
        return None;
    }

    let file = ::std::fs::File::open(path)
        .expect("failed to open the file"); 
    let mut _symbols: Vec<Symbol> = Vec::new();
    match serde_json::from_reader(file)
    {
        Ok(s)=>{
            _symbols = s;
            for sym in _symbols.iter_mut()
            {
                sym.header = base64::decode(&sym.header_b64).unwrap_or(Vec::new());
                sym.header_b64 = String::new();
                sym.export_dir.data = base64::decode(&sym.export_dir.data_b64).unwrap_or(Vec::new());
                sym.export_dir.data_b64 = String::new();
            }
            return Some(_symbols);
        },
        _=>{
            debug!("Failed to Load Symbols");
            return None
        },
    }
}

fn get_export_rva(
	import: &String,
    is_symbols: &mut bool,
	function: &ImportAddressValue,
    vaddr: u64,
	function_symbols: &mut Vec<Symbol>) -> (u64, String)
{
    //println!("{:?}", function);
	for dll in function_symbols.iter_mut()
	{
		let dll_name = import.to_lowercase();
        if dll.name.ends_with(&dll_name)
        {
            *is_symbols = true;
            dll.virtual_address = vaddr;
            dll.is_imported = true;
        	for export in dll.exports.iter()
        	{
        	    if function.func_name == export.name
        	    {
        	    	return (export.rva, export.name.clone());
        	    }
        	}
        }
	}
	return (0, String::new());
}

pub fn get_peb_addr_config(config: &Config, mode: &Mode) -> u64
{
    match *mode
    {
        Mode::Mode32=>{
            return config.x86.pe_file.peb_address32;
        },
        Mode::Mode64=>{
            return config.x86.pe_file.peb_address64;
        },
        _=>{},
    }
    return PEB_ADDRESS;
}

pub fn get_teb_addr_config(config: &Config, mode: &Mode) -> u64
{
    match *mode
    {
        Mode::Mode32=>{
            return config.x86.pe_file.teb_address32;
        },
        Mode::Mode64=>{
            return config.x86.pe_file.teb_address64;
        },
        _=>{},
    }
    return TEB_ADDRESS;
}

fn get_symbols_paths(config: &Config, mode: &Mode) ->String
{
    match *mode
    {
        Mode::Mode32=>{
            debug!("Loading Mode32 Symbols");
            return config.x86.pe_file.function_symbol32.clone();
        },
        Mode::Mode64=>{
            debug!("Loading Mode64 Symbols");
            return config.x86.pe_file.function_symbol64.clone();
        },
        _=>{},
    }
    return String::new();
}

fn get_dll_addr_config(config: &Config, mode: &Mode) -> u64
{
    match *mode
    {
        Mode::Mode32=>{
            return config.x86.pe_file.dll_address32;
        },
        Mode::Mode64=>{
            return config.x86.pe_file.dll_address64;
        },
        _=>{},
    }
    return DLL_ADDRESS;
}

/// get virtual address of kernel32!BaseThreadInitThunk and assign to eax
pub fn get_inital_eax(analysis: &mut Analysisx86) -> i64
{
    match analysis.symbols
    {
        Some(ref mut symbols)=>{
            for dll in symbols.iter()
            {
                if dll.name.ends_with("kernel32.dll")
                {
                    for export in dll.exports.iter(){
                        if export.ordinal == 1 
                        {
                            let vaddr = dll.virtual_address + export.rva;
                            debug!("kernel32.dll!{} rva=0x{:x}", export.name, vaddr);
                            return vaddr as i64;
                        }
                    }
                }
            }
        },
        None=>{},
    }
    return 0;
}

pub fn build_dll_memory(
    analysis: &mut Analysisx86,
    mem_manager: &mut MemoryManager)
{
    match analysis.symbols{
        Some(ref mut sym)=>{
            for s in sym
            {
                //header
                mem_manager.list.push(
                MemoryBounds
                {
                    base_addr: s.virtual_address as usize,
                    size: s.header.len(),
                    mem_type: MemoryType::Library,
                    binary: &mut [0u8; 0], // empty
                });

                mem_manager.list.push(
                MemoryBounds
                {
                    base_addr: (s.virtual_address as usize) + s.export_dir.offset,
                    size: s.export_dir.size,
                    mem_type: MemoryType::ExportDir,
                    binary: &mut [0u8; 0], // empty
                });
            }
        },
        None=>{},
    }
}

pub fn get_dll_binary(
    bounds_address: usize, 
    analysis: &mut Analysisx86) -> Option<&mut [u8]>
{
    match analysis.symbols{
        Some(ref mut sym)=>{
            for s in sym
            {
                if bounds_address == s.virtual_address as usize {
                    return Some(&mut s.header);

                } else if bounds_address == (s.virtual_address as usize) + s.export_dir.offset{
                    return Some(&mut s.export_dir.data);
                }
            }
        },
        None=>{},
    }
    return None;
}

pub fn build_dll_import_addresses<'a>(
	analysis: &mut Analysisx86,
    mem_image: &mut MemoryBounds<'a>,
    config: &Config)
{
    println!("\tLOADING SYMBOLS");
    let mut function_symbols: Vec<Symbol> = match load_symbol(&get_symbols_paths(config, &analysis.xi.mode))
    {
        Some(symbols)=>{
            symbols
        },
        _=>return,
    };
    println!("\tWRITING IMPORT OFFSETS");
    let mut fill_in_address: Vec<(usize, u64)> = Vec::new();
    match analysis.header.import_table{
        Some(ref mut iat)=>
        {
            let mut vaddr: u64 = get_dll_addr_config(config, &analysis.xi.mode);
            for import in iat.iter_mut(){
                match analysis.header.mode
                {
                    Mode::Mode32=>{
                        if vaddr >= PEB_ADDRESS{
                            break;
                        }
                    },
                    Mode::Mode64=>{
                        if vaddr >= PEB_ADDRESS_64{
                            break;
                        }
                    }
                    _=>{},
                }
                
                import.virtual_address = vaddr;
                for func in import.import_address_list.iter_mut()
                {
                	let (rva, func_name) = get_export_rva(
                		&import.name,
                        &mut import.is_symbols, 
                		&func, 
                        vaddr,
                		&mut function_symbols);
                    if rva != 0 
                    {
                        func.func_name = func_name;
                    	func.virtual_address = Some(import.virtual_address + rva);
                    	// Insert Address Into image
                    	fill_in_address.push(
                    		(func.ft_address as usize, 
                    		(import.virtual_address + rva)));
                    }
                }            
                vaddr += VIRTUAL_ADDRESS_OFFSET;
            }
        }
        None=>{},
    }
    analysis.symbols = Some(function_symbols);
    for &(offset, vaddr) in fill_in_address.iter()
    {
        // add address to binary
        write_address(
            offset, 
            vaddr, 
            analysis,
            mem_image.binary);
    }
}

fn write_address(
    address: usize, 
    value: u64, 
    analysis: &mut Analysisx86,
    binary: &mut [u8])
{
    
    if address >= binary.len()
    {
        return;
    }

    let size = match analysis.header.mode
    {
        Mode::Mode64=>{
             address + 8
        },
        Mode::Mode32=>{
             address + 4
        },
        Mode::Mode16=>{
             address + 2
        },
        _=>0,
    };

    let mut temp = value as u64;
    let mut i = address;
    while i < size {
        let byte = (temp & 0xff) as u8;
        binary[i] = byte;
        temp = temp >> 8;
        i+=1;
    }
}

pub fn build_image<'a>(
    _binary: &'a mut [u8],
    _header: &Header,
    _new_binary: &'a mut [u8],
    ) -> (bool, bool)
{
    let mut is_corrupted = false;
    if _header.size_of_image == 0 
    {
        return (false, is_corrupted);
    }
    match _header.section_table
    {
        Some(ref sections)=>
        {
        	_new_binary[.._header.file_alignment as usize].copy_from_slice(&_binary[.._header.file_alignment as usize]);
            for section in sections.iter()
            {
                let section_begin = section.virtual_address as usize;
                let mut section_end = (section.virtual_address as usize) + (section.size_of_raw_data as usize);
                let raw_begin = section.pointer_to_raw_data as usize;
                let mut raw_end = raw_begin + section.size_of_raw_data as usize;
                // create image with length if the binary is corrupted.
                if raw_begin > _binary.len()
                {
                    if section.name.contains(".text")
                    {
                        println!("is_corrupted");
                        is_corrupted = true;
                    } else {
                        println!("Section {} is_corrupted", section.name);
                    }
                    continue;
                }
                if raw_end > _binary.len()
                {
                    if section.name.contains(".text")
                    {
                        println!("is_corrupted");
                        is_corrupted = true;
                    } else {
                        println!("Section {} is_corrupted", section.name);
                    }
                    raw_end = _binary.len();
                    section_end = (raw_end - raw_begin) + section_begin;
                }
                if section_end > _new_binary.len()
                {
                    section_end = _new_binary.len()-1;
                    let new_raw_size = section_end - section_begin;
                    raw_end = raw_begin + new_raw_size;
                }
                
                let mut permissions = String::new();
                if section.is_read()
                {
                    permissions.push('R');
                }
                if section.is_write()
                {
                    permissions.push('W');
                }
                if section.is_execute()
                {
                    permissions.push('X');
                }

                let mut section_type = String::new();
                if section.is_code()
                {
                    section_type.push('C');
                }
                if section.is_init_data()
                {
                    section_type.push('D');
                }
                if section.is_uninit_data()
                {
                    section_type.push('U');
                }
                println!("\tADDING SECTION: {:10} | start: {:8x}, end: {:8x} | {:4} | {:4}", 
                    section.name,
                    section_begin, section_end,
                    permissions,
                    section_type
                );
                _new_binary[section_begin..section_end].copy_from_slice(&_binary[raw_begin..raw_end]);
                
            }
            return (true, is_corrupted);
        },
        None=>return (false, is_corrupted),
    }
}

pub fn ignore_section_data(
    analysis: &mut Analysisx86)
{
    if analysis.header.size_of_image == 0 
    {
        return;
    }
    match analysis.header.section_table
    {
        Some(ref sections)=>
        {
            for section in sections.iter()
            {
                if !section.is_execute() && !section.is_code()
                {
                    let section_begin = (section.virtual_address as u64) + analysis.header.image_base;
                    let section_end = section.size_of_raw_data as usize;
                    analysis.address_tracker.insert(section_begin, section_end);
                }
            }
            return;
        },
        None=>return,
    }
}

pub fn get_section_name(
    offset: u64,
    analysis: &mut Analysisx86) -> String
{
    if analysis.header.size_of_image == 0 
    {
        return String::new();
    }
    match analysis.header.section_table
    {
        Some(ref sections)=>
        {
            for section in sections.iter()
            {
                let section_begin = (section.virtual_address as u64) + analysis.header.image_base;
                let section_end = section.size_of_raw_data;

                if section_begin <= offset && offset < section_end
                {
                    return section.name.clone();
                }
            }
        },
        None=>{},
    }
    return String::new();
}

pub fn build_teb(
    analysis: &mut Analysisx86,
    config: &Config,
    ) -> Vec<u8>
{
    println!("BUILDING TEB");
    match analysis.xi.mode
    {
        Mode::Mode32=>{
            let teb_addr: u32 = get_teb_addr_config(
                config, 
                &Mode::Mode32) as u32;
            let peb_addr: u32 = get_peb_addr_config(
                config, 
                &Mode::Mode32) as u32;
            let teb_struct = ThreadInformationBlock32
            {
                seh_frame:                0,  //0x00
                stack_base:               0,  //0x04
                stack_limit:              0,  //0x08
                subsystem_tib:            0,  //0x0C
                fiber_data:               0,  //0x10
                arbitrary_data:           0,  //0x14
                self_addr:                teb_addr,  //0x18
                environment_ptr:          0,  //0x1C
                process_id:               1234,  //0x20
                thread_id:                4567,  //0x24
                active_rpc_handle:        0,  //0x28
                tls_addr:                 0,  //0x2C  thread  local storage
                peb_addr:                 peb_addr,  //0x30
                last_error:               0,  //0x34
                critical_section_count:   0,  //0x38
                csr_client_thread:        0,  //0x3C
                win32_thread_info:        0,  //0x40
                win32_client_info:        [0; 31],    //0x44
                fastsyscall:              0,  //0xC0
                current_locale:           0,  //0xC4
                fp_software_status_reg:   0,  //0xC8
                reserved:                 [0; 27],    //0xCC
                exception_code:           0,  //0x1A4
                activation_context_stack: [0; 20],    //0x1A8
                spare_bytes:              [0; 24],    //0x1BC
            };
            let teb_binary: Vec<u8> = serialize(&teb_struct).unwrap();
            return teb_binary;
        },
        Mode::Mode64=>{
            let teb_addr: u64 = get_teb_addr_config(
                config, 
                &Mode::Mode64);
            let peb_addr: u64 = get_peb_addr_config(
                config, 
                &Mode::Mode64);
            let teb_struct = ThreadInformationBlock64
            {
                seh_frame:                0,  //0x00
                stack_base:               0,  //0x08
                stack_limit:              0,  //0x10
                subsystem_tib:            0,  //0x18
                fiber_data:               0,  //0x20
                arbitrary_data:           0,  //0x28
                self_addr:                teb_addr,  //0x30
                //End of NT subsystem independent part
                environment_ptr:          0,  //0x38
                process_id:               1234,  //0x40
                thread_id:                4567,  //0x48
                active_rpc_handle:        0,  //0x50
                tls_addr:                 0,  //0x58 
                peb_addr:                 peb_addr,  //0x60
                last_error:               0,  //0x68
                critical_section_count:   0,  //0x6C
                csr_client_thread:        0,  //0x70
                win32_thread_info:        0,  //0x78
                user32_reserved:          [0; 26], //0x80
                user_reserved:            [0; 5], //0xe8
                fastsyscall:              0,  //0x100
                current_locale:           0,  //0x108
                fp_software_status_reg:   0,  //0x10c
                reserved:                 [0; 27], //0x110
                reserved1:                [0; 27], //0x110
                exception_code:           0,  //0x2c0
                activation_context_stack: 0,  //0x2c8
                spare_bytes:              [0; 24],    //0x2d0
            };
            let teb_binary: Vec<u8> = serialize(&teb_struct).unwrap();
            return teb_binary;
        },
        _=>{},
    }
    return Vec::new();
}

pub fn build_peb(
    analysis: &mut Analysisx86,
    config: &Config,
    ) -> Vec<u8>
{
    println!("BUILDING PEB");
    match analysis.xi.mode
    {
        Mode::Mode32=>{
            let peb_addr: u32 = get_peb_addr_config(
                config, 
                &Mode::Mode32) as u32;
            let mut peb_struct = ProcessEnvironmentBlock32
            {
                inherited_addr_space:                   false, //0x000
                read_image_fileexec_options:            false, //0x001
                being_debugged:                         false, //0x002
                bit_field:                              0,  //0x003
                mutant:                                 0,  //0x004
                image_base_address:  analysis.base as u32,  //0x008
                peb_ldr_data:                           0,  //0x000C
                process_parameters:                     0,  //0x0010
                sub_system_data:                        0,  //0x0014
                process_heap:                           0,  //0x0018
                fast_peb_lock:                          0,  //0x001C
                atl_thunk_s_list_ptr:                   0,  //0x0020
                ifeo_key:                               0,  //0x0024
                cross_process_flags:                    0,  //0x0028
                kernel_callback_table:                  0,  //0x002C
                system_reserved:                        0,  //0x0030
                atl_thunk_slist_ptr32:                  0,  //0x0034
                api_set_map:                            0,  //0x0038
                tls_expansion_counter:                  0,  //0x003C
                tls_bitmap:                             0,  //0x0040
                tls_bitmap_bits:                        [0; 2],      //0x0044
                read_only_shared_memory_base:           0,  //0x004C
                hotpatch_information:                   0,  //0x0050
                read_only_static_server_data:           0,  //0x0054
                ansi_code_page_data:                    0,  //0x0058
                oem_code_page_data:                     0,  //0x005C
                unicode_case_table_data:                0,  //0x0060
                number_of_processors:                   0,  //0x0064
                nt_global_flag:                         0,  //0x0068
                critical_section_timeout:               0,  //0x0070
                heap_segment_reserve:                   0,  //0x0078
                heap_segment_commit:                    0,  //0x007C
                heap_de_commit_total_free_threshold:    0,  //0x0080
                heap_de_commit_free_block_threshold:    0,  //0x0084
                number_of_heaps:                        0,  //0x0088
                maximum_number_of_heaps:                0,  //0x008C
                process_heaps:                          0,  //0x0090
                gdi_shared_handle_table:                0,  //0x0094
                process_starter_helper:                 0,  //0x0098
                gdi_d_c_attribute_list:                 0,  //0x009C
                loader_lock:                            0,  //0x00A0
                os_major_version:                       0,  //0x00A4
                os_minor_version:                       0,  //0x00A8
                os_build_number:                        0,  //0x00AC
                os_csd_version:                         0,  //0x00AE
                os_platform_id:                         0,  //0x00B0
                image_subsystem:                        0,  //0x00B4
                image_subsystem_major_version:          0,  //0x00B8
                image_subsystem_minor_version:          0,  //0x00BC
                active_process_affinity_mask:           0,  //0x00C0
                gdi_handle_buffer:                      [0; 17],   //0x00C4
                gdi_handle_buffer1:                     [0; 17],   //0x00C4 Hack
                post_process_init_routine:              0,  //0x014C
                tls_expansion_bitmap:                   0,  //0x0150
                tls_expansion_bitmap_bits:              [0; 32],   //0x0154
                session_id:                             1234,  //0x01D4
                app_compat_flags:                       0,  //0x01D8
                app_compat_flags_user:                  0,  //0x01E0
                pshim_data:                             0,  //0x01E8
                app_compat_info:                        0,  //0x01EC
                csd_version:                            [0;  8],      //0x01F0
                activation_context_data:                0,  //0x01F8
                process_assembly_storage_map:           0,  //0x01FC
                system_default_activation_context_data: 0,  //0x0200
                system_assembly_storage_map:            0,  //0x0204
                minimum_stack_commit:                   0,  //0x0208
                fls_callback:                           0,  //0x020C
                fls_list_head:                          0,  //0x0210
                fls_bitmap:                             0,  //0x0218
                fls_bitmap_bits:                        [0; 4],      //0x021C
                fls_high_index:                         0,  //0x022C
                wer_registration_data:                  0,  //0x0230
                wer_ship_assert_ptr:                    0,  //0x0234
                pcontext_data:                          0,  //0x0238
                pimage_header_hash:                     0,  //0x023C
                tracing_flags:                          0,  //0x0240
            };
            peb_struct.peb_ldr_data = peb_addr + ::std::mem::size_of::<ProcessEnvironmentBlock32>() as u32;
            debug!("peb_ldr_data 0x{:x} 0x{:x}", 
                peb_struct.peb_ldr_data, 
                ::std::mem::size_of::<ProcessEnvironmentBlock32>());
            let mut peb_binary: Vec<u8> = serialize(&peb_struct).unwrap();
            let mut peb_ldr_data = build_peb_ldr_data(analysis, peb_struct.peb_ldr_data as u64);
            peb_binary.append(&mut peb_ldr_data);
            return peb_binary;
        },
        Mode::Mode64=>{
            let peb_addr: u64 = get_peb_addr_config(
                config, 
                &Mode::Mode64);

            let mut peb_struct = ProcessEnvironmentBlock64
            {
                inherited_addr_space:                   false, 
                read_image_fileexec_options:            false, 
                being_debugged:                         false, 
                bit_field:                              [0; 5],  
                mutant:                                 0,  
                image_base_address:  analysis.base as u64,  
                peb_ldr_data:                           0,  
                process_parameters:                     0,  
                sub_system_data:                        0,  
                process_heap:                           0,  
                fast_peb_lock:                          0,  
                atl_thunk_s_list_ptr:                   0,  
                ifeo_key:                               0,  
                cross_process_flags:                    0,  
                kernel_callback_table:                  0,  
                system_reserved:                        0,  
                atl_thunk_slist_ptr32:                  0,  
                api_set_map:                            0,  
                tls_expansion_counter:                  0,  
                tls_bitmap:                             0,  
                tls_bitmap_bits:                        [0; 2],      
                read_only_shared_memory_base:           0,  
                hotpatch_information:                   0,  
                read_only_static_server_data:           0,  
                ansi_code_page_data:                    0,  
                oem_code_page_data:                     0,  
                unicode_case_table_data:                0,  
                number_of_processors:                   0,  
                nt_global_flag:                         0,  
                critical_section_timeout:               0,  
                heap_segment_reserve:                   0,  
                heap_segment_commit:                    0,  
                heap_de_commit_total_free_threshold:    0,  
                heap_de_commit_free_block_threshold:    0,  
                number_of_heaps:                        0,  
                maximum_number_of_heaps:                0,  
                process_heaps:                          0,  
                gdi_shared_handle_table:                0,  
                process_starter_helper:                 0,  
                gdi_d_c_attribute_list:                 0,  
                loader_lock:                            0,  
                os_major_version:                       0,  
                os_minor_version:                       0,  
                os_build_number:                        0,  
                os_csd_version:                         0,  
                os_platform_id:                         0,  
                image_subsystem:                        0,  
                image_subsystem_major_version:          0,  
                image_subsystem_minor_version:          0,  
                active_process_affinity_mask:           0,  
                gdi_handle_buffer:                      [0; 30],     
                post_process_init_routine:              0,  
                tls_expansion_bitmap:                   0,  
                tls_expansion_bitmap_bits:              [0; 32],   
                session_id:                             1234,  
                app_compat_flags:                       0,  
                app_compat_flags_user:                  0,  
                pshim_data:                             0,  
                app_compat_info:                        0,  
                csd_version:                            [0; 16],      
                activation_context_data:                0,  
                process_assembly_storage_map:           0,  
                system_default_activation_context_data: 0,  
                system_assembly_storage_map:            0,  
                minimum_stack_commit:                   0,  
                fls_callback:                           0,  
                fls_list_head:                          0,  
                fls_bitmap:                             0,  
                fls_bitmap_bits:                        [0; 3],      
                fls_high_index:                         0,  
                wer_registration_data:                  0,  
                wer_ship_assert_ptr:                    0,  
                pcontext_data:                          0,  
                pimage_header_hash:                     0,  
                tracing_flags:                          0,  
            };
            peb_struct.peb_ldr_data = peb_addr + ::std::mem::size_of::<ProcessEnvironmentBlock64>() as u64;
            debug!("peb_ldr_data 0x{:x} 0x{:x}", 
                peb_struct.peb_ldr_data, 
                ::std::mem::size_of::<ProcessEnvironmentBlock64>());
            let mut peb_binary: Vec<u8> = serialize(&peb_struct).unwrap();
            let mut peb_ldr_data = build_peb_ldr_data(analysis, peb_struct.peb_ldr_data);
            peb_binary.append(&mut peb_ldr_data);
            return peb_binary;
        },
        _=>{},
    }
    return Vec::new();
}

fn pwchar_to_vector(input: &str) -> (usize, usize, Vec<u8>)
{
    let mut output: Vec<u8> = Vec::new();
    let mut max_size = 0;
    let mut length = 0;
    match UTF_16LE.encode(input, EncoderTrap::Strict)
    {
        Ok(i) => {
            if i.len() > 0{
                max_size = i.len()-1;
            }
            length = i.len();
            output = i;
        },
        _=>{},
    }
    return (length, max_size, output);
}

fn get_load_order(analysis: &mut Analysisx86) -> Vec<(u64, String, String)>
{
    let mut load_list: Vec<(u64, String, String)> = Vec::new();
    //Get last virtual address
    let mut last_virtual_address: u64 = match analysis.header.import_table
    {
        Some(ref iat)=>{
            match iat.last()
            {
                Some(ref dll)=>dll.virtual_address,
                None=>DLL_ADDRESS,
            }
        },
        None=>DLL_ADDRESS,
    };

    last_virtual_address += VIRTUAL_ADDRESS_OFFSET;
    if last_virtual_address >= PEB_ADDRESS{
        return load_list;
    }

    // get NTDLL
    match analysis.symbols
    {
        Some(ref mut symbols)=>{
            for dll in symbols.iter_mut()
            {
                let name = dll.name.split("\\").last().unwrap_or("");
                if dll.name.ends_with("ntdll.dll")
                {
                    if dll.virtual_address == 0
                    {
                        dll.virtual_address = last_virtual_address;
                        last_virtual_address += VIRTUAL_ADDRESS_OFFSET;
                    }
                    load_list.push((dll.virtual_address, dll.name.clone(), 
                        String::from(name)));
                    break;
                }
            }
            if last_virtual_address >= PEB_ADDRESS{
                return load_list;
            }
            // get KERNEL32
            for dll in symbols.iter_mut()
            {
                let name = dll.name.split("\\").last().unwrap_or("");
                if dll.name.ends_with("kernel32.dll")
                {
                    if dll.virtual_address == 0
                    {
                        dll.virtual_address = last_virtual_address;
                        last_virtual_address += VIRTUAL_ADDRESS_OFFSET;
                    }
                    load_list.push((dll.virtual_address, dll.name.clone(),
                        String::from(name)));
                    break;
                }
            }
        },
        None=>{},
    }
    // load all imports
    match analysis.header.import_table
    {
        Some(ref iat)=>{
            for dll in iat.iter()
            {
                if dll.name != "kernel32.dll" && dll.name != "ntdll.dll"
                {
                    load_list.push((dll.virtual_address, 
                        format!("{}{}", "C:\\Windows\\System32\\", dll.name),
                        dll.name.clone()));
                }               
            }
        },
        None=>{},
    };

    // add the rest of the symbols
    match analysis.symbols
    {
        Some(ref mut symbols)=>{
            for dll in symbols.iter_mut()
            {
                if last_virtual_address >= PEB_ADDRESS{
                    break;
                }
                let name = dll.name.split("\\").last().unwrap_or("");
                let mut _is_added = false;
                for &(ref _addr, ref _path, ref basename) in load_list.iter()
                {
                    if dll.name.ends_with(basename)
                    {
                        _is_added = true;
                        break;
                    }
                }
                if !_is_added
                {
                    if dll.virtual_address == 0
                    {
                        dll.virtual_address = last_virtual_address;
                        last_virtual_address += VIRTUAL_ADDRESS_OFFSET;
                    }
                    load_list.push((dll.virtual_address, 
                    dll.name.clone(),
                    String::from(name)));
                }
            }
        },
        None=>{},
    }

    return load_list;
}

fn build_peb_ldr_data(
    analysis: &mut Analysisx86,
    offset: u64, // start of next section
    ) -> Vec<u8>
{
    match analysis.xi.mode
    {
        Mode::Mode32=>{

            let mut _flink: u64 = offset + ::std::mem::size_of::<PebLoaderData32>() as u64;
            let mut _blink: u64 = 0;
            let mut _start_of_list: u64 = offset + 0x0C;
            let mut _end_of_list: u64 = 0;
            let mut peb_ldr_data = PebLoaderData32
            {
                length: 0x28, //0x00
                initialized: [0; 4], //0x04
                ss_handle: 0, //0x08
                in_load_order_module_list: [0, _flink as u32], //0x0C
                in_memory_order_module_list: [0, (_flink as u32) + 8], //0x14
                in_initialization_order_module_list: [0, (_flink as u32) + 16], //0x1C
                entry_in_progress: 0, //0x24
                shutdown_in_progress: 0, //0x28
                shutdown_thread_id: 0, //0x2C
            };
            
            // build the linked list
            let mut _module_count = 1;

            //add self
            _blink = _start_of_list; // pointer to flink
            let module_base = analysis.base as u64;
            
            let mut self_module = build_peb_ldr_table_entry(
                &Mode::Mode32,
                _flink,
                _blink,
                module_base,
                "C:\\this.exe",
                "this.exe",
                false);

            // save end of list if there are no imports or symbols
            _end_of_list = _flink;

            //set next pointer
            let new_offset = self_module.len() as u64;
            _blink = _flink;
            _flink += new_offset;

            let load_order = get_load_order(analysis);

            let symbol_count =  load_order.len();
            _module_count += symbol_count;

            for (index, &(ref module_base, ref path, ref basename)) in load_order.iter().enumerate()
            {
                
                let mut is_end = false;
                if index+1 == symbol_count
                {
                    _end_of_list = _flink;
                    _flink = _start_of_list;
                    is_end = true;
                }
                let mut new_module = build_peb_ldr_table_entry(
                    &Mode::Mode32,
                    _flink,
                    _blink,
                    *module_base,
                    path,
                    basename,
                    is_end);

                _blink = _flink;
                _flink += new_module.len() as u64;
                self_module.append(&mut new_module);
            }

            peb_ldr_data.in_load_order_module_list[0] = _end_of_list as u32;
            peb_ldr_data.in_memory_order_module_list[0] = (_end_of_list as u32) + 8;
            peb_ldr_data.in_initialization_order_module_list[0] = (_end_of_list as u32) + 16;
            
            let mut peb_ldr_binary: Vec<u8> = serialize(&peb_ldr_data).unwrap();
            peb_ldr_binary.append(&mut self_module);
            return peb_ldr_binary;
        },
        Mode::Mode64=>{
            let mut _flink: u64 = offset + ::std::mem::size_of::<PebLoaderData64>() as u64;
            let mut _blink: u64 = 0;
            let mut _start_of_list: u64 = offset + 0x0C;
            let mut _end_of_list: u64 = 0;
            let mut peb_ldr_data = PebLoaderData64
            {
                length: 0x58, //0x00
                initialized: [0; 4], //0x04
                ss_handle: 0, //0x08
                in_load_order_module_list: [0, _flink as u64], //0x10
                in_memory_order_module_list: [0, (_flink as u64) + 16], //0x20
                in_initialization_order_module_list: [0, (_flink as u64) + 32], //0x30
                entry_in_progress: 0, //0x40
                shutdown_in_progress: 0, //0x48
                shutdown_thread_id: 0, //0x50
            };
            
            // build the linked list
            let mut _module_count = 1;

            //add self
            _blink = _start_of_list; // pointer to flink
            let module_base = analysis.base as u64;
            
            let mut self_module = build_peb_ldr_table_entry(
                &Mode::Mode64,
                _flink,
                _blink,
                module_base,
                "C:\\this.exe",
                "this.exe",
                false);

            // save end of list if there are no imports or symbols
            _end_of_list = _flink;

            //set next pointer
            let new_offset = self_module.len() as u64;
            _blink = _flink;
            _flink += new_offset;

            let load_order = get_load_order(analysis);

            let symbol_count =  load_order.len();
            _module_count += symbol_count;

            for (index, &(ref module_base, ref path, ref basename)) in load_order.iter().enumerate()
            {
                
                let mut is_end = false;
                if index+1 == symbol_count
                {
                    _end_of_list = _flink;
                    _flink = _start_of_list;
                    is_end = true;
                }
                let mut new_module = build_peb_ldr_table_entry(
                    &Mode::Mode64,
                    _flink,
                    _blink,
                    *module_base,
                    path,
                    basename,
                    is_end);

                _blink = _flink;
                _flink += new_module.len() as u64;
                self_module.append(&mut new_module);
            }

            peb_ldr_data.in_load_order_module_list[0] = _end_of_list as u64;
            peb_ldr_data.in_memory_order_module_list[0] = (_end_of_list as u64) + 16;
            peb_ldr_data.in_initialization_order_module_list[0] = (_end_of_list as u64) + 32;
            
            let mut peb_ldr_binary: Vec<u8> = serialize(&peb_ldr_data).unwrap();
            peb_ldr_binary.append(&mut self_module);
            return peb_ldr_binary;
            
        },
        _=>{},
    }
    return Vec::new();
}


fn build_peb_ldr_table_entry(
    mode: &Mode,
    offset: u64,
    blink: u64,
    dll_base: u64,
    dll_path: &str,
    dll_name: &str,
    is_end: bool,
    ) -> Vec<u8>
{
    match *mode
    {
        Mode::Mode32=>{
            let (path_length, path_max, mut path_buffer) = pwchar_to_vector(dll_path);
            let (name_length, name_max, mut name_buffer) = pwchar_to_vector(dll_name);
            let predicted_length: u32 = (::std::mem::size_of::<PebLdrTableEntry32>() as u32) + path_length as u32 + name_length as u32;
            let mut _flink: u32 = (offset as u32) + predicted_length;

            if is_end{
                _flink = offset as u32;
            }
            let peb_ldr_data = PebLdrTableEntry32
            {
                in_load_order_links: [blink as u32, _flink], //0x00
                in_memory_order_links: [(blink as u32) + 8, _flink + 8], //0x08
                in_initialization_order_links: [(blink as u32) + 16, _flink + 16], //0x10
                dll_base:                      0,  //0x18
                entry_point:                   dll_base as u32, //0x1C
                size_of_image:                 0, //0x20
                full_dll_name: WinUnicodeSting32{
                    length: path_length as u16,
                    maximum_length: path_max as u16,
                    buffer: 0,
                }, //0x24
                base_dll_name: WinUnicodeSting32{
                    length: name_length as u16,
                    maximum_length: name_max as u16,
                    buffer: 0,
                }, //0x2C
                flags: 0, //0x34
                load_count: 0, //0x38
                tls_index: 0, //0x3A
                hash_links: [0; 2], //0x3C
            };
            let mut peb_ldr_binary: Vec<u8> = serialize(&peb_ldr_data).unwrap();

            //append string buffers
            peb_ldr_binary.append(&mut path_buffer);
            peb_ldr_binary.append(&mut name_buffer);
            return peb_ldr_binary;
        },
        Mode::Mode64=>{
            let (path_length, path_max, mut path_buffer) = pwchar_to_vector(dll_path);
            let (name_length, name_max, mut name_buffer) = pwchar_to_vector(dll_name);
            let predicted_length: u64 = (::std::mem::size_of::<PebLdrTableEntry64>() as u64) + path_length as u64 + name_length as u64;
            let mut _flink: u64 = (offset as u64) + predicted_length;

            if is_end{
                _flink = offset as u64;
            }
            let peb_ldr_data = PebLdrTableEntry64
            {
                in_load_order_links: [blink as u64, _flink], //0x00
                in_memory_order_links: [(blink as u64) + 16, _flink + 16], //0x10
                in_initialization_order_links: [(blink as u64) + 32, _flink + 32], //0x20
                dll_base:                      0,  //0x30
                entry_point:                   dll_base as u64, //0x38
                size_of_image:                 0, //0x40
                full_dll_name: WinUnicodeSting64{
                    length: path_length as u32,
                    maximum_length: path_max as u32,
                    buffer: 0,
                }, //0x48
                base_dll_name: WinUnicodeSting64{
                    length: name_length as u32,
                    maximum_length: name_max as u32,
                    buffer: 0,
                }, //0x58
                flags: 0, //0x60
                load_count: 0, //0x68
                tls_index: 0, //0x6C
                hash_links: [0; 2], //0x6E
            };
            let mut peb_ldr_binary: Vec<u8> = serialize(&peb_ldr_data).unwrap();

            //append string buffers
            peb_ldr_binary.append(&mut path_buffer);
            peb_ldr_binary.append(&mut name_buffer);
            return peb_ldr_binary;
        },
        _=>{},
    }
    return Vec::new();
}

fn get_section_table(
    cursor: &[u8],
    num_sections: &u16) -> Result<Vec<Section>, String>
{
    let section_table: SectionTable = match section_table(cursor, *num_sections)
    {
        Ok((_i, section_table))=>section_table,
        Err(err)=> return Err(format!("{:?}", err)),
    };
    let mut sections: Vec<Section> = Vec::new();
    for section in section_table.section_headers.iter()
    {
        sections.push(Section
        {
            name: section.name.clone(),
            virtual_size: section.virtual_size as u64,
            virtual_address: section.virtual_address as u64,
            size_of_raw_data: section.size_of_raw_data as u64,
            pointer_to_raw_data: section.pointer_to_raw_data as u64,
            characteristics: section.characteristics as u32,
        });
    }
    return Ok(sections);
}

#[derive(Debug,Clone,Serialize)]
pub struct ImportAddressValue 
{
    pub ord: u64,
    pub func_name: String,
    pub file_offset: u64,
    pub address: u64,
    pub iat_offset: u64,
    pub ft_address: u64,
    pub virtual_address: Option<u64>,
}

fn get_imports(
    header: &Header,
    input: &[u8],
    cursor: &[u8],
    num_sections: &u16) -> Result<Vec<Import>, String>
{
    if header.image_data_directory == 0 {
        return Err(format!("image data directory is null"));
    }
    let section_table: SectionTable = match section_table(
        cursor, 
        *num_sections)
    {
        Ok((_i, section_table))=>section_table,
        Err(err)=>return Err(format!("{:?}", err)),
    };
    let idd_index = rva_to_file_offset(
        header.image_data_directory as usize, 
        &section_table);
    if idd_index > input.len()
    {
        return Err(format!("binary is corrupted"));
    }
    let import_table: ImportTable = match import_table(&input[idd_index..])
    {
        Ok((_i, import_table))=> import_table,
        Err(err)=> return Err(format!("{:?}", err)),
    };

    let mut import_list: Vec<Import> = Vec::new();

    for import_descriptor in import_table.image_import_descriptors
    {
        let dllname = match import_dll_name(&input[rva_to_file_offset(import_descriptor.name as usize, &section_table,)..],)
        {
            Ok((_i, dllname)) => dllname,
            Err(err)=> return Err(format!("{:?}", err)),
        };
        let mut dll_import = Import{
            name: dllname.name.to_lowercase(),
            virtual_address: 0,
            import_address_list: Vec::new(),
            is_symbols: false,
        };

        let (import_addresses, addr_mask, voffset) = match header.mode 
        {
            Mode::Mode32=>{
                match import_address_table32(&input[rva_to_file_offset(import_descriptor.original_first_thunk as usize, &section_table,)..],)
                {
                    Ok((_i, import_lookup)) => {
                        let mut generic: Vec<u64> = Vec::new();
                        for x in &import_lookup.elements
                        {
                            generic.push(*x as u64);
                        }
                        (generic, 0x80000000, 4u64)
                    },
                    Err(err)=> return Err(format!("{:?}", err)),
                }
            },
            Mode::Mode64=>{
                match import_address_table64(&input[rva_to_file_offset(import_descriptor.original_first_thunk as usize, &section_table,)..],)
                {
                    Ok((_i, import_lookup)) => (import_lookup.elements, 0x8000000000000000, 8u64),
                    Err(err)=> return Err(format!("{:?}", err)),
                }
            },
            _=>return Err(format!("PE Header Unsupported for {:?}", header.mode)),
        };

        for (off, addr) in import_addresses.iter().enumerate() 
        {
            let mut import_function_name: String = String::new();
            let import_ordinal: u64 = off as u64;
            let mut new_ordinal: u64 = off as u64;
            if *addr & addr_mask == 0x0 {
                let name_offset = rva_to_file_offset(*addr as usize, &section_table,);
                if name_offset < input.len(){ 
                    match image_import_by_name(&input[name_offset..],) 
                    {
                        Ok((_i, import_function)) => {
                            import_function_name = import_function.name
                        }
                        Err(err)=> return Err(format!("{:?}", err)),
                    }
                } 
            } else {
                new_ordinal = (addr ^ addr_mask) as u64;
            }
            let import_value = ImportAddressValue{
                ord: new_ordinal,
                func_name: import_function_name,
                file_offset: rva_to_file_offset(*addr as usize,&section_table) as u64,
                address: *addr,
                iat_offset: (rva_to_file_offset(import_descriptor.first_thunk as usize,&section_table) + (off * voffset as usize)) as u64,
                ft_address: import_descriptor.first_thunk as u64 + (import_ordinal * voffset),
                virtual_address: None,
            };
            dll_import.import_address_list.push(import_value);
        }
        import_list.push(dll_import);
    }
    return Ok(import_list);
}

pub fn get_pe_header(
    header: &mut Header,
	binary: &mut [u8],
    config: &Config) -> Result<i32, String>
{
    debug!("get_pe_header()");
    let pe_offset = match dos_header(&binary)
    {
      Ok((_cursor, o))=>o.e_lfanew as usize,
      Err(_)=>return Err(String::from("Error incomplete DOS Header")),
    };
    if pe_offset > binary.len()
    {
        return Err(String::from("Error incomplete DOS Header or might be MS-DOS"));
    }
    let (cursor, pe_header) = match pe_header(
        &binary[pe_offset..]) 
    {
        Ok((cursor, pe_header))=> {
            match pe_header.image_optional_header {
                ImageOptionalHeaderKind::Pe32(ioh) =>
                {
                    header.image_base = match config.x86.start_address{ 0=>ioh.image_base.into(), _=>config.x86.start_address }; 
                    header.base_of_code = ioh.base_of_code.into();
                    header.size_of_code = ioh.size_of_code.into();
                    header.base_of_data = ioh.base_of_data.into();
                    header.address_of_entry_point = match config.x86.entry_point{ 0=>ioh.address_of_entry_point.into(), _=>config.x86.entry_point };
                    header.stack_size = ioh.size_of_stack_reserve.into();
                    header.section_alignment = ioh.section_alignment.into();
                    header.file_alignment = ioh.file_alignment.into();
                    header.mode = Mode::Mode32;
                    header.image_data_directory = ioh.image_data_directory[ImageDataIndex::ImportTable as usize].virtual_address as u64;
                    header.import_table = None;
                    header.size_of_image = ioh.size_of_image.into();
                    header.section_table = None;
                },
                ImageOptionalHeaderKind::Pe32Plus(ioh) =>
                {
                    header.image_base = match config.x86.start_address{ 0=>ioh.image_base.into(), _=>config.x86.start_address };
                    header.base_of_code = ioh.base_of_code.into(); 
                    header.size_of_code = ioh.size_of_code.into();
                    header.base_of_data = 0; 
                    header.address_of_entry_point = match config.x86.entry_point{ 0=>ioh.address_of_entry_point.into(), _=>config.x86.entry_point };
                    header.stack_size = ioh.size_of_stack_reserve.into();
                    header.section_alignment = ioh.section_alignment.into();
                    header.file_alignment = ioh.file_alignment.into();
                    header.mode = Mode::Mode64;
                    header.image_data_directory = ioh.image_data_directory[ImageDataIndex::ImportTable as usize].virtual_address as u64;
                    header.import_table = None;
                    header.size_of_image = ioh.size_of_image.into();
                    header.section_table = None;
                },
            }
            (cursor, pe_header)
        },
        Err(_)=>return Err(String::from("Error incomplete PE Header")),
    };
    
    /* Fix up file_alignment
    This appears to be the total size of the portions of the image that the 
    loader has to worry about. It is the size of the region starting at the 
    image base up to the end of the last section. The end of the last 
    section is rounded up to the nearest multiple of the section alignment.
    */
    if header.section_alignment > header.file_alignment && header.section_alignment > 0 {
        let remainder = header.size_of_image % header.section_alignment;
        if remainder < header.section_alignment
        {
            header.size_of_image = (header.size_of_image - remainder) + header.section_alignment;
        }
    } else if header.file_alignment > 0 
    {
        let remainder = header.size_of_image % header.file_alignment;
        if remainder < header.file_alignment
        {
            header.size_of_image = (header.size_of_image - remainder) + header.file_alignment;
        }
    }

    // Get imports
    header.import_table = match get_imports(
        &header,
        binary, 
        cursor, 
        &pe_header.coff_header.num_sections)
    {
        Ok(import_table)=>Some(import_table),
        _=>None,
    };
    // Get section table
    header.section_table = match get_section_table(
        cursor, 
        &pe_header.coff_header.num_sections)
    {
        Ok(sections)=>Some(sections),
        _=>None,
    };
    return Ok(0);
}