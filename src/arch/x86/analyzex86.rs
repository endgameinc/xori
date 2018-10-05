//analyzex86.rs
use analysis::signature_analysis::SigAnalyzer;
use arch::x86::archx86::*;
use analysis::analyze::*;
use analysis::data_analyzer::*;
use arch::x86::cpux86::*;
use analysis::formats::peloader::*;
use arch::x86::emulatex86::*;
use std::collections::VecDeque;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use num::{Num, NumCast};
use num::traits::AsPrimitive;
//use std::num::Wrapping;
//use std::ops::BitOr;
use std::ops::Bound::Included;

const CHUNK_SIZE: usize = 100; // 15 bytes

#[derive(Debug,Serialize, Deserialize)]
pub struct DetailInfo
{
    pub op_index: u8,
    pub contents: String,
}

#[derive(Debug,Serialize, Deserialize)]
pub struct InstructionInfo
{
    pub instr: Instruction<X86Detail>,
    pub detail: Vec<DetailInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export
{
    pub name: String,
    pub ordinal: u16,
    pub rva: u64,
    pub forwarder: bool,
    pub forwarder_name: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportDirectory
{
    pub offset: usize,
    pub size: usize,
    pub data_b64: String,
    pub data: Vec<u8>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol
{
    pub name: String,
    pub exports: Vec<Export>,
    pub virtual_address: u64,
    pub is_imported: bool,
    pub header_b64: String,
    pub header: Vec<u8>,
    pub export_dir: ExportDirectory,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AnalysisType
{
    Data,
    Code,
}

pub struct Analysisx86
{
    pub xi: Xori, 
    pub header: Header,
    pub base: usize,
    pub address_tracker: BTreeMap<u64, usize>,
    pub instr_info: BTreeMap<u64, InstructionInfo>,
    pub functions: Vec<FuncInfo>,
    pub symbols: Option<Vec<Symbol>>,
    pub sig_analyzer: SigAnalyzer
}

impl Analysisx86
{
    /// Add the jump address to the state's current
    /// function jump table.
    pub fn add_jump(&mut self,
        address: &u64,
        offset: u64,
        left: i64,
        right: i64)
    {
        let mut is_local_function = false;
        for func in self.functions.iter_mut()
        {
            if func.address == right as u64 && left == 0
            {
                is_local_function = true;
                func.xrefs.insert(offset);
            }
        }
        for func in self.functions.iter_mut()
        {
            if func.address == *address{
                if (left == 0 && right == 0) || is_local_function
                {
                    // add it as a return for non conditional jump
                    func.returns.insert(offset);
                }
                func.jumps.insert(offset, Jump
                {
                    left: left,
                    right: right,
                });
                
                return; 
            }
        }
        return;
    }
    /// Add the address of the return to the state's
    /// current function return list.
    pub fn add_return(&mut self,
        address: &u64,
        offset: u64)
    {
        for func in self.functions.iter_mut()
        {
            if func.address == *address{
                func.returns.insert(offset);
                return; 
            }
        }
        return;
    }
    /// Check if the return value is valid
    pub fn add_return_value(&mut self,
        value: u64,
        address: &u64,
        offset: u64) -> (bool, u64)
    {
        for func in self.functions.iter_mut()
        {
            if func.address == *address{
                func.returns.insert(offset);
                match func.return_values.get(&value)
                {
                    Some(rval)=>{
                        debug!("return is 0x{:x}", value);
                        return (true, *rval);
                    }
                    None=>{
                        return (false, 0); 
                    }
                }
            }
        }
        return (false, 0);
    }
    /// Add the dest address of the call to the function tracker
    /// if the dest address already exists add the xref address to the list
    /// Check if the dest address points to an import apicall
    pub fn add_func(&mut self,
        calling_function: u64,
        offset: u64,
        return_offset: u64,
        memory_address: u64, 
        destination_offset: u64, 
        memory_type: MemoryType,
        import_only: bool) -> Option<String>
    {
        // ignore any address that could not be analyzed
        if destination_offset == 0 {
            return None;
        }
        // check if the call exists already
        match self.check_func_exists(
            calling_function,
            offset, 
            return_offset,
            destination_offset) 
        {
            Some(position)=>return Some(self.functions[position].name.clone()),
            None=>{},
        }
        // Initalize the new function
        let mut new_function = FuncInfo{
            address: destination_offset,
            mem_address: 0,
            xrefs: BTreeSet::new(),
            name: String::new(),
            argc: 0,
            mem_type: match import_only { true=>MemoryType::Import, false=>memory_type },
            returns: BTreeSet::new(),
            return_values: BTreeMap::new(),
            jumps: BTreeMap::new(),
        };

        if offset != 0
        {
            new_function.xrefs.insert(offset);
        }
        if return_offset != 0
        {
            new_function.return_values.insert(return_offset, calling_function);
        }

        // Specific OS based requirements here
        match self.header.binary_type
        {
            BinaryType::PE |
            BinaryType::PEEXE | 
            BinaryType::PEDLL | 
            BinaryType::PESYS =>
            {
                // check if the function is on the IAT
                match self.header.import_table{
                    Some(ref iat)=>{
                        for import in iat.iter()
                        {
                            for function in import.import_address_list.iter(){
                                match function.virtual_address
                                {
                                    Some(ref addr)=>
                                    {
                                        if new_function.address == *addr
                                        {
                                            new_function.name = format!("{}!{}", 
                                                import.name, function.func_name);
                                            new_function.mem_type = MemoryType::Import;
                                            new_function.mem_address = function.ft_address;
                                            break;
                                        } 
                                    }
                                    None=>{
                                        // Fall through 
                                        if memory_address == (function.ft_address + self.base as u64) 
                                        {
                                            new_function.name = format!("{}!{}", 
                                                import.name, function.func_name);
                                            new_function.mem_type = MemoryType::Import;
                                            new_function.mem_address = function.ft_address;
                                            break;
                                        }
                                    },
                                }
                                
                            }
                        }
                    }
                    None=>{},
                }
                // check if function exists in json pdb files
                if new_function.name.is_empty()
                {
                    new_function.name = format!("sub_{:x}", destination_offset);
                    match self.symbols
                    {
                        Some(ref sym)=>{
                            for dll in sym.iter()
                            {
                                let base_addr = dll.virtual_address;
                                for export in dll.exports.iter()
                                {
                                    let vaddr = base_addr + export.rva;
                                    if new_function.address == vaddr
                                    {
                                        new_function.name = format!("{}!{}", 
                                            dll.name, export.name);
                                        new_function.mem_type = MemoryType::Peb;
                                        new_function.mem_address = vaddr;
                                        break;
                                    } 
                                }
                            }
                        },
                        None=>{},
                    }
                }
            },
            _=>{},
        }

        // If the jump is a function that already exists

        // If the instruction is a jump
        if import_only
        {
            if !new_function.name.is_empty()
            {
                self.functions.push(new_function);
                let position = self.functions.len()-1;
                return Some(self.functions[position].name.clone());
            }

        } else {
            // if the instruction is a call
            self.functions.push(new_function);
            let position = self.functions.len()-1;
            return Some(self.functions[position].name.clone());
        }
        return None;
    }
    fn check_func_exists(&mut self,
        _calling_func: u64,
        _cur_address: u64,
        _return_address: u64,
        _jmp_offset: u64) -> Option<usize>
    {
        for (position, func) in self.functions.iter_mut().enumerate()
        {
            if func.address == _jmp_offset{
                // add address to xrefs
                if _cur_address != 0 {
                    func.xrefs.insert(_cur_address);
                }
                if _return_address != 0 {
                    func.return_values.insert(_return_address, _calling_func);
                }
                return Some(position);
            }
        }
        return None;
    }
}

#[derive(Debug, Clone)]
pub struct Statex86
{
    pub offset: usize,
    pub cpu: CPUStatex86, 
    pub stack: Vec<u8>,
    pub current_function_addr: u64,
    pub emulation_enabled: bool,
    pub loop_state: LoopState,
    pub analysis_type: AnalysisType,
}

impl Statex86 {
    pub fn stack_read(
        &mut self,
        address: i64,
        value_size: usize) -> i64
    {
        if address == 0 {
            return 0;
        }

        let index_check: isize = ((self.cpu.stack_address as isize) - (address as isize)) - (self.cpu.address_size as isize - (address as isize % self.cpu.address_size as isize));
        if index_check < 0
        {
            debug!("stack overflow2");
            return 0;
        }
        let index: isize = index_check;
        if 0 <= index && index < self.stack.len() as isize {
            match value_size
            {
                1 => {
                    read_int::<i8>(index as usize, 0, &self.stack)
                        .unwrap_or(0) as i64
                },
                2 => {
                    read_int::<i16>(index as usize, 0, &self.stack)
                        .unwrap_or(0) as i64
                },
                4 => {
                    read_int::<i32>(index as usize, 0, &self.stack)
                        .unwrap_or(0) as i64
                },
                8 => {
                    read_int::<i64>(index as usize, 0, &self.stack)
                        .unwrap_or(0) as i64
                },
                _ => 0
            }
        } else {
            0
        }
    }

    pub fn stack_write(
        &mut self,
        address: u64,
        value: i64,
        value_size: usize,
        bounds_size: usize)
    {
        let stack_max = self.cpu.stack_address as isize - bounds_size as isize;
        if (address as isize - (self.cpu.address_size as isize)) < stack_max
        {
            debug!("stack overflow");
            return;
        }
        let index_check: isize = ((self.cpu.stack_address as isize) - (address as isize)) - (self.cpu.address_size as isize - (address as isize % self.cpu.address_size as isize));
        if index_check < 0
        {
            debug!("stack overflow");
            return;
        }
        let offset = index_check + (self.cpu.address_size as isize + (address as isize % self.cpu.address_size as isize));
        if offset as usize >= self.stack.len(){
            self.stack.resize(offset as usize, 0);
        }
        let mut i = index_check;
        let mut temp = value as u64;
        while i < (index_check + value_size as isize)
        {
            let byte = (temp & 0xff) as u8;
            self.stack[i as usize] = byte;
            temp = temp >> 8;
            i+=1;
        }    
    }
}

#[derive(Debug,Clone,Serialize,PartialEq, Deserialize)]
pub enum MemoryType
{
    Invalid,
    Image,
    Stack,
    Import,
    Heap,
    Teb,
    Peb,
    Library,
    ExportDir,
    Handler,
}

#[derive(Debug)]
pub struct MemoryBounds<'a>
{
    pub base_addr: usize,
    pub size: usize,
    pub mem_type: MemoryType,
    pub binary: &'a mut [u8],
}

#[derive(Debug)]
pub struct MemoryManager<'a>
{
    pub list: Vec<MemoryBounds<'a>>,
}

pub fn read_int<T: Num + NumCast + Copy + 'static>(
     _offset: usize,
     _address: usize,
     _binary: &[u8]) -> Option<T>
    where u64: AsPrimitive<T>
{
    if let Some(start) = _offset.checked_sub(_address) {
        // start does not underflow, good!

        let count_to_read = ::std::mem::size_of::<T>();

        if let Some(end) = start.checked_add(count_to_read) {
            if end <= _binary.len() {
                // end is in bounds, also good!

                let mut result: u64 = 0;

                for byte_index in 0..count_to_read {
                    result |= (_binary[start + byte_index] as u64) << (byte_index * 8);
                }

                return NumCast::from::<u64>(result)
                    .map(|x: u64| x.as_());
            }
        }
    }

    return None;
}

fn binary_write(
    address: usize, 
    value: u64, 
    value_size: usize,
    base_addr: usize,
    binary: &mut [u8])
{
    let offset: isize = address as isize - base_addr as isize;
    let size: usize = offset as usize + value_size;
    if offset >= binary.len() as isize || offset >= binary.len() as isize
    {
        return;
    }
    let mut temp = value as u64;
    let mut i = offset as usize;
    while i < size {
        let byte = (temp & 0xff) as u8;
        binary[i] = byte;
        temp = temp >> 8;
        i+=1;
    }
}

fn binary_read(
    address: usize,  
    value_size: usize,
    base_addr: usize,
    binary: &mut [u8]) -> i64
{
    match value_size
    {
        1 => {
            read_int::<u8>(address, base_addr, binary)
                .unwrap_or(0) as i8 as i64
        },
        2 => {
            read_int::<u16>(address, base_addr, binary)
                .unwrap_or(0) as i16 as i64
        },
        4 => {
            read_int::<u32>(address, base_addr, binary)
                .unwrap_or(0) as i32 as i64
        },
        8 => {
            read_int::<u64>(address, base_addr, binary)
                .unwrap_or(0) as i64
        },
        _ => 0
    }
}

pub fn transmute_integer_to_vec(
    value: usize, 
    length: usize) -> Vec<u8>
{
    let mut new_bytes:Vec<u8> = Vec::new();
    let mut temp = value;
    let mut i = 0;
    while i < length 
    {
        let byte = (temp & 0xff) as u8;
        new_bytes.push(byte);
        temp = temp >> 8;
        i+=1;
    }
    return new_bytes;
}

pub fn transmute_integer(
    value: usize, 
    length: usize) -> String
{
    let mut new_string = String::new();
    let mut temp = value;
    let mut i = 0;
    while i < length 
    {
        let byte = (temp & 0xff) as u8;
        if 0x20 <= byte && byte <= 0x7e 
        {
            new_string.push(byte as char);
        }
        temp = temp >> 8;
        i+=1;
    }
    return new_string;
}

fn read_stack_string(
    address: usize,
    addr_size: usize,
    binary: &mut [u8],
    _is_data: bool) -> String
{
    if address == 0{
        return String::new();
    }
    let stack_start = binary.len()-1;
    let mut index = address as isize - 1;
    if stack_start < (index as usize) || (index as usize) > binary.len()
    {
        return String::new();
    }
    let mut is_string: bool = false;
    let max_string_size = address + 32;
    let mut possible_string: Vec<u8> = Vec::new();
    
    if binary.len() == 0 
    {
        return String::new(); 
    }
    if 0x00 < binary[index as usize] && binary[index as usize] < 0xFF
    {
        while index > 0 && index - addr_size as isize > 0
        {
            let mut i = index-(addr_size as isize -1);
            let mut continue_string = true;
            while i <= index  
            {
                if 0x00 < binary[i as usize] && binary[i as usize] < 0x7e &&
                    possible_string.len() <= max_string_size 
                {
                    is_string = true;
                    possible_string.push(binary[i as usize]);
                }
                else {
                    continue_string = false;
                    break;
                }
                i+=1;
            }
            if !continue_string{ break; }
            index-=addr_size as isize;
        }
    }
    
    if is_string{
        let mut new_string = String::new();
        for c in possible_string
        {
            if 0x20 <= c && c <= 0x7e {
                new_string.push(c as char);
            }
            else {
                new_string.push_str(&format!("\\x{:02X}", c));
            } 
        }
        return new_string;
    }
    return String::new();
}
fn read_string(
    address: usize,
    base_addr: usize,
    binary: &mut [u8],
    is_data: bool) -> String
{
    let mut is_string: bool = false;
    let max_string_size = address + 32;
    let mut possible_string: Vec<u8> = Vec::new();
    let mut index = address-base_addr; 
    if index < binary.len()
    {
        if !is_data && (binary[index] == 0x00 || (0x00 < binary[index] && binary[index] < 0xFF)) 
        {
            // valid printable ascii
            while (possible_string.len() <= max_string_size &&
                   index < binary.len() && 
                   index+1 < binary.len()) && 
                   0x20 <= binary[index] && binary[index] <= 0x7e 
            {
                // unicode check
                if binary[index] == 0x00 
                {
                    if (0x00 < binary[index+1] && binary[index+1] < 0xFF) && binary[index+1] !=0x00 
                    {
                        possible_string.push(binary[index+1]);
                        is_string = true;
                    } else {
                        is_string = false;
                    }
                } else if 0x00 < binary[index] && binary[index] < 0xFF{
                    possible_string.push(binary[index]);
                    is_string = true;
                } else {
                    is_string = false;
                }
                index+=1;
            }
        } else if 0x00 < binary[index] && binary[index] < 0xFF
        {
            while (possible_string.len() <= max_string_size &&
                   index < binary.len() && 
                   index+1 < binary.len()) && 
                   0x00 < binary[index] && binary[index] <= 0xfe
            {
                is_string = true;
                possible_string.push(binary[index]);
                index+=1;
            }
        }
    }
    if is_string{
        let mut new_string = String::new();
        for c in possible_string
        {
            if 0x20 <= c && c <= 0x7e {
                new_string.push(c as char);
            }
            else {
                new_string.push_str(&format!("\\x{:02X}", c));
            } 
        }
        return new_string;
    }
    return String::new();
}

impl <'a>MemoryManager<'a>
{
    pub fn write(
        &mut self,
        offset: usize, 
        value: u64,
        value_size: usize) -> MemoryType
    {
        for bounds in self.list.iter_mut()
        {
            if offset >= bounds.base_addr && offset < (bounds.base_addr + bounds.size)
            {
                match bounds.mem_type
                {
                    MemoryType::Image=>{
                        binary_write(
                            offset,
                            value,
                            value_size,
                            bounds.base_addr,
                            bounds.binary);
                    },
                    _=>{},
                }
                return bounds.mem_type.clone();
            }
        }
        return MemoryType::Invalid;
    }

    pub fn read(
        &mut self,
        offset: usize, 
        value_size: usize,
        analysis: &mut Analysisx86) -> i64
    {
        for bounds in self.list.iter_mut()
        {
            if offset >= bounds.base_addr && offset < (bounds.base_addr + bounds.size)
            {
                match bounds.mem_type
                {
                    MemoryType::Image=>{
                        return binary_read(
                            offset,
                            value_size,
                            bounds.base_addr,
                            bounds.binary);
                    },
                    MemoryType::Teb=>{
                        debug!("TEB is read");
                        return binary_read(
                            offset,
                            value_size,
                            bounds.base_addr,
                            bounds.binary);
                    },
                    MemoryType::Peb=>{
                        
                        let value = binary_read(
                            offset,
                            value_size,
                            bounds.base_addr,
                            bounds.binary);
                        debug!("PEB is read 0x{:x}", value);
                        return value;
                    },
                    MemoryType::Library=>{
                        debug!("DLL HEADER is read 0x{:x}", offset);
                        get_dll_binary(bounds.base_addr, analysis);
                        let value = match get_dll_binary(bounds.base_addr, analysis){
                            Some(bin)=>{
                                binary_read(
                                    offset,
                                    value_size,
                                    bounds.base_addr,
                                    bin)
                            }
                            None=>0,
                        };
                        return value;
                    },
                    MemoryType::ExportDir=>{
                        debug!("DLL EXPORT is read 0x{:x}", offset);
                        get_dll_binary(bounds.base_addr, analysis);
                        let value = match get_dll_binary(bounds.base_addr, analysis){
                            Some(bin)=>{
                                binary_read(
                                    offset,
                                    value_size,
                                    bounds.base_addr,
                                    bin)
                            }
                            None=>0,
                        };
                        return value;
                    },
                    _=>{},
                }
            }
        }
        debug!("read failed");
        return 0;
    }

    pub fn is_stack(
        &mut self,
        offset: usize)->(bool, usize, usize)
    {
        for bounds in self.list.iter_mut()
        {
            if offset >= bounds.base_addr && offset <= (bounds.base_addr + bounds.size)
            {
                if bounds.mem_type == MemoryType::Stack
                {
                    return (true, bounds.base_addr, bounds.size);
                }
            }
        }
        return (false, 0, 0);
    }

    pub fn get_mem_type(
        &mut self,
        offset: usize) -> MemoryType
    {
        for bounds in self.list.iter_mut()
        {
            if offset >= bounds.base_addr && offset < (bounds.base_addr + bounds.size)
            {
                return bounds.mem_type.clone();
            }
        }
        return MemoryType::Invalid;
    }

    pub fn get_image_by_type(
        &mut self,
        mem_type: MemoryType) -> &mut [u8]
    {
        for bounds in self.list.iter_mut()
        {
            if bounds.mem_type == mem_type
            {
                return bounds.binary;
            }
        }
        return &mut [0u8; 0]
    }

    pub fn get_base_addr_by_type(
        &mut self,
        mem_type: MemoryType) -> usize
    {
        for bounds in self.list.iter_mut()
        {
            if bounds.mem_type == mem_type
            {
                return bounds.base_addr;
            }
        }
        return 0;
    }

    pub fn get_size_by_type(
        &mut self,
        mem_type: MemoryType) -> usize
    {
        for bounds in self.list.iter_mut()
        {
            if bounds.mem_type == mem_type
            {
                return bounds.size;
            }
        }
        return 0;
    }

    pub fn check_for_string(
        &mut self,
        analysis: &mut Analysisx86,
        state: &mut Statex86,
        offset: usize,
        _value_size: usize) -> String
    {
        for bounds in self.list.iter_mut()
        {
            if offset >= bounds.base_addr && 
            offset < (bounds.base_addr + bounds.size)
            {
                match bounds.mem_type
                {
                    MemoryType::Image=>{
                        let mut is_data = false;
                        match analysis.header.section_table
                        {
                            Some(ref sections)=>{
                                for section in sections.iter()
                                {
                                    if (section.name == ".data" || 
                                        section.name == ".rdata" ||
                                        section.name == ".idata") && 
                                        offset >= (section.virtual_address as usize +
                                        analysis.base as usize) &&
                                        offset < (section.virtual_address as usize + 
                                        analysis.base as usize) +
                                        section.virtual_size as usize
                                        {
                                            is_data = true;
                                        }
                                }
                            },
                            None=>{},
                        }
                        return read_string(
                            offset,
                            bounds.base_addr,
                            bounds.binary,
                            is_data);
                    },
                    MemoryType::Teb=>{
                        return String::from("[ALERT!: TEB is accessed]");
                    },
                    MemoryType::Peb=>{
                        return String::from("[ALERT!: PEB is accessed]");
                    },
                    MemoryType::Stack=>{
                        let new_offset = (state.cpu.stack_address as usize) - offset;

                        return read_stack_string(
                            new_offset,
                            state.cpu.address_size as usize,
                            &mut state.stack,
                            false);
                    }
                    _=>{},
                }
            }
        }
        return String::new();
    }

    pub fn is_executable(
        &mut self,
        offset: usize,
        analysis: &mut Analysisx86)-> bool
    {
        match analysis.header.section_table
        {
            Some(ref sections)=>{
                for section in sections.iter()
                {
                    let section_begin = (section.virtual_address as usize) + analysis.header.image_base as usize;
                    let section_end = (section_begin as usize) + section.size_of_raw_data as usize;
                    if section_begin <= offset && offset < section_end
                    {
                        return section.is_execute();
                    }
                }
            },
            None=>{},
        }
        return false;
    }
}

pub enum AnalysisResult
{
    End,
    Failed,
    Continue,
}

fn check_instr_already_analyzed(
    offset: u64, 
    analysis: &mut Analysisx86)->bool
{
    if (offset as i64) < 0 
    {
        return false;
    }
    if analysis.instr_info.get(&offset).is_some()
    {
        return true;
    }
    let mut start = offset-16;
    if (offset as i64) < 16 
    {
        start = 0;
    }
    let end=offset+16;
    if start > end
    {
        return false;
    }
    for (key, instr) in analysis.instr_info.range((Included(&start), Included(&end))){
        if *key < offset && offset < (*key+(instr.instr.size as u64))
        {
            return true;
        } 
    }
    return false;
}

/// Used for ignoring Non-Executable sections
fn check_address_already_analyzed(
    offset: u64, 
    address_tracker: &BTreeMap<u64, usize>)->bool
{
    if address_tracker.get(&offset).is_some()
    {
        return true;
    }
    for (key, size) in address_tracker.iter(){
        if *key < offset && offset < (*key+(*size as u64)+1)
        {
            return true;
        } 
    }
    return false;
}

/// analyze an individual instruction on how to handle cpu
pub fn analyze_instructionx86(
    item: &mut Instruction<X86Detail>,
    analysis: &mut Analysisx86,
    mem_manager: &mut MemoryManager,
    state: &mut Statex86,
    queue: &mut VecDeque<Statex86>,
    )-> AnalysisResult
{
    if item.skipped_bytes > 0 
    {
        let _offset: usize = item.offset as usize;
        if check_instr_already_analyzed(
            item.offset as u64,
            analysis)
        { 
            return AnalysisResult::Failed;
        }
        let bytes_instr = InstructionInfo
        {
            instr: item.clone(),
            detail: Vec::new(),
        };
        analysis.instr_info.insert(bytes_instr.instr.offset as u64, bytes_instr);
        return AnalysisResult::Failed;
    }
    
    if !state.emulation_enabled {
        if check_instr_already_analyzed(
            item.offset as u64,
            analysis)
        { 
            return AnalysisResult::End;
        }
    }

    // Update the EIP
    state.cpu.regs.eip.value=item.offset as i64;

    // add instruction
    let mut valid_instr = InstructionInfo
      {
        instr: item.clone(),
        detail: Vec::new(),
    };
    
    // Start analyzing instructions
    emulate_instructions(
        valid_instr.instr.offset as u64, 
        &mut valid_instr, 
        analysis,
        mem_manager,
        state);

    match check_data_transfer_instructions(
        valid_instr.instr.offset as u64, 
        &mut valid_instr, 
        analysis,
        mem_manager,
        state)
    {
        Some(offset_state)=>{
          queue.push_back(offset_state);  
        },
        None=>{},
    }

    // (Call is always taken unless an import or invalid)
    match check_call(
        valid_instr.instr.offset as u64, 
        &mut valid_instr, 
        analysis,
        mem_manager,
        state)
    {
        (Some(left_state), Some(right_state))=>{
            if right_state.offset != 0 {
                debug!("call_right 0x{:x} @ 0x{:x}", right_state.offset, valid_instr.instr.offset);
                queue.push_front(right_state);
                if state.emulation_enabled
                {
                    analysis.instr_info.insert(valid_instr.instr.offset as u64, valid_instr);
                    return AnalysisResult::End;  
                }
            }
            if left_state.offset != 0 {
                let (is_padding, new_offset) = check_if_padding(left_state.offset, analysis, mem_manager);
                if is_padding
                {
                    //Add return to parent function
                    analysis.add_return(
                        &state.current_function_addr,
                        valid_instr.instr.offset);
                    valid_instr.detail.push(
                        DetailInfo
                        {
                            op_index: 0, 
                            contents: format!("FUNC 0x{:x} END", &state.current_function_addr)
                        });
                    if !state.emulation_enabled
                    {
                        let mut data_state = left_state.clone();
                        data_state.offset = new_offset;
                        data_state.current_function_addr = 0;
                        data_state.analysis_type = AnalysisType::Data;
                        queue.push_back(data_state);
                    }
                } else {
                    queue.push_back(left_state);
                }
            }
            analysis.instr_info.insert(valid_instr.instr.offset as u64, valid_instr);
            return AnalysisResult::End;
        },
        (None, Some(right_state))=>{
            if right_state.offset != 0 {
                debug!("call_right 0x{:x} @ 0x{:x}", right_state.offset, valid_instr.instr.offset);
                queue.push_front(right_state);
            }
            analysis.instr_info.insert(valid_instr.instr.offset as u64, valid_instr);
            return AnalysisResult::End;
        },
        (Some(left_state), None)=>{
            if left_state.offset != 0 {
                let (is_padding, new_offset) = check_if_padding(left_state.offset, analysis, mem_manager);
                if is_padding
                {
                    //Add return to parent function
                    analysis.add_return(
                        &state.current_function_addr,
                        valid_instr.instr.offset);
                    valid_instr.detail.push(
                        DetailInfo
                        {
                            op_index: 0, 
                            contents: format!("FUNC 0x{:x} END", &state.current_function_addr)
                        });
                    if !state.emulation_enabled
                    {
                        let mut data_state = left_state.clone();
                        data_state.offset = new_offset;
                        data_state.current_function_addr = 0;
                        data_state.analysis_type = AnalysisType::Data;
                        queue.push_back(data_state);
                    }
                } else {
                    queue.push_front(left_state);
                }
            } else {
                //Analyze data after this function
                if !state.emulation_enabled
                {
                    let mut data_state = left_state.clone();
                    data_state.offset = valid_instr.instr.offset as usize + valid_instr.instr.size;
                    data_state.current_function_addr = 0;
                    data_state.analysis_type = AnalysisType::Data;
                    queue.push_back(data_state);
                }
            }
            analysis.instr_info.insert(valid_instr.instr.offset as u64, valid_instr);
            return AnalysisResult::End;
        },
        _=>{},
    }
    
    // analyze jmp/branch instructions
    match check_branch_instructions(
        valid_instr.instr.offset as u64, 
        &mut valid_instr, 
        analysis,
        mem_manager,
        state) 
    {
        (Some(left_state), Some(right_state), is_taken)=>{
            if right_state.offset != 0
            {
                if state.emulation_enabled && is_taken {
                    queue.push_front(right_state);
                    analysis.instr_info.insert(valid_instr.instr.offset as u64, valid_instr);
                    return AnalysisResult::End;
                }
                else {
                    queue.push_front(right_state);
                }
            }
            if left_state.offset != 0 {
                if state.emulation_enabled && !is_taken {
                    queue.push_front(left_state);
                    analysis.instr_info.insert(valid_instr.instr.offset as u64, valid_instr);
                    return AnalysisResult::End;
                }
                else {
                    queue.push_back(left_state);
                }
            }
            analysis.instr_info.insert(valid_instr.instr.offset as u64, valid_instr);
            return AnalysisResult::End;
        },
        (None, Some(right_state), is_taken)=>{
            if right_state.offset != 0
            {
                if state.emulation_enabled && is_taken {
                    queue.push_front(right_state);
                    analysis.instr_info.insert(valid_instr.instr.offset as u64, valid_instr);
                    return AnalysisResult::End;
                }
                else {
                    queue.push_front(right_state);
                }
            }
            analysis.instr_info.insert(valid_instr.instr.offset as u64, valid_instr);
            return AnalysisResult::End;
        },
        (Some(left_state), None, is_taken)=>{
            if left_state.offset != 0 {
                if state.emulation_enabled && !is_taken {
                    queue.push_front(left_state);
                    analysis.instr_info.insert(valid_instr.instr.offset as u64, valid_instr);
                    return AnalysisResult::End;
                }
                else {
                    queue.push_back(left_state);
                }
            }
            analysis.instr_info.insert(valid_instr.instr.offset as u64, valid_instr);
            return AnalysisResult::End;
        },
        _=>{},
    }
    
    // finish analysis
    let (is_return, return_state) = check_return(
        valid_instr.instr.offset as u64, 
        &mut valid_instr, 
        analysis,
        mem_manager,
        state);

    if is_return
    {
        debug!("is return");
        match return_state
        {
            Some(ret_state)=>{
                if ret_state.offset != 0 {
                    queue.push_front(ret_state);
                }
            },
            None=>{},
        }
        if !state.emulation_enabled {
            let (is_padding, new_offset) = check_if_padding(
                valid_instr.instr.offset as usize + valid_instr.instr.size, 
                analysis, 
                mem_manager);
            if is_padding
            {
                let post_analysis: Statex86 = Statex86 
                {
                    offset: new_offset,
                    cpu: state.cpu.clone(),
                    stack: Vec::new(),
                    current_function_addr: 0,
                    emulation_enabled: state.emulation_enabled,
                    loop_state: state.loop_state.clone(),
                    analysis_type: AnalysisType::Data,
                };
                queue.push_back(post_analysis);
            }
        }
        analysis.instr_info.insert(valid_instr.instr.offset as u64, valid_instr);
        return AnalysisResult::End;
    }
    
    // default
    analysis.instr_info.insert(valid_instr.instr.offset as u64, valid_instr);
    return AnalysisResult::Continue;
}

pub fn check_instruction_exists(
    offset: u64, 
    analysis: &mut Analysisx86) -> Option<Instruction<X86Detail>>
{
    
    match analysis.instr_info.get_mut(&(offset))
    {
        Some(info)=>{
            return Some(info.instr.clone());
        },
        None=>{},
    }
    return None;
}

pub fn recurse_disasmx86(
    analysis: &mut Analysisx86,
    mem_manager: &mut MemoryManager,
    state: &mut Statex86,
    queue: &mut VecDeque<Statex86>,
    )-> bool
{
    let chunk_length = CHUNK_SIZE;
    let image_base = mem_manager.get_base_addr_by_type(MemoryType::Image);
    let image_size = mem_manager.get_size_by_type(MemoryType::Image);

    while state.offset < (image_base + image_size)
    {
        let mut vec: Vec<Instruction<X86Detail>> = Vec::new();

        // check for empty bytes within chunk to ignore
        if state.offset > analysis.base
        {
            let mut temp_chunk = chunk_length;
            let mut check_length = (state.offset-analysis.base) + chunk_length;
            let image_length = image_size-1;
            if check_length > image_length
            {
                check_length = image_length;
                temp_chunk = image_length - (state.offset-analysis.base);
            }
            if mem_manager.get_image_by_type(MemoryType::Image)
                [(state.offset-analysis.base)..check_length] == *vec![0u8 ; temp_chunk].as_slice()
            {
                state.offset += chunk_length;
                continue;
            }
        }
        
        match state.analysis_type
        {
            AnalysisType::Data=>{
                if check_instr_already_analyzed(state.offset as u64, analysis)
                {
                    return true;
                }
                match analyze_datax86(
                    state.offset, 
                    analysis, 
                    mem_manager,
                    state,
                    queue)
                {
                    AnalysisResult::Failed=>{},
                    AnalysisResult::End=>{
                        return true;
                    },
                    AnalysisResult::Continue=>{
                        state.offset+=state.cpu.address_size as usize;
                    },
                }
            },
            AnalysisType::Code=>{

                if check_address_already_analyzed(
                    state.offset as u64,
                    &analysis.address_tracker)
                { 
                    return true;
                }

                match check_instruction_exists(state.offset as u64, analysis)
                {
                    Some(mut instruction)=>{
                        state.offset = instruction.address as usize + instruction.size;
                        match analyze_instructionx86(
                            &mut instruction,
                            analysis,
                            mem_manager,
                            state,
                            queue)
                        {
                            AnalysisResult::End=>{
                                return true;
                            },
                            _=>{},
                        }
                    },
                    None=>{
                        analysis.xi.disasm(
                            mem_manager.get_image_by_type(MemoryType::Image), 
                            image_size,
                            analysis.base, 
                            state.offset,
                            chunk_length, 
                            &mut vec);
                        if vec.len() > 0
                        {
                            let mut last_instr_addr = state.offset + chunk_length; // default
                            
                            for instruction in vec.iter_mut()
                            {
                                match analyze_instructionx86(
                                    instruction,
                                    analysis,
                                    mem_manager,
                                    state,
                                    queue)
                                {
                                    AnalysisResult::Failed=>{
                                        last_instr_addr = instruction.address as usize + 
                                        instruction.skipped_bytes as usize;
                                    },
                                    AnalysisResult::End=>{
                                        return true;
                                    },
                                    AnalysisResult::Continue=>{                                       
                                        last_instr_addr = instruction.address as usize + instruction.size;
                                    },
                                }
                            }
                            state.offset = last_instr_addr;
                        }

                    },
                }
            },
        }
        
    }
    return true;
}
