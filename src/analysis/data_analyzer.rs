//data_analyzer.rs
// analyzes that that is not traversed in the analysis queue
use arch::x86::archx86::X86Detail;
use arch::x86::analyzex86::*;
pub use disasm::*;
use std::collections::VecDeque;
use std::collections::BTreeMap;
use std;

// 1) Determine if data
// - Consecutive zeros 
// - Consecutive C
// - A Failed instruction
// 2) Check for address size boundaries
const MAX_SIGNATURE_SIZE: usize = 16;
pub fn check_if_padding(
    offset: usize, 
    analysis: &mut Analysisx86, 
    mem_manager: &mut MemoryManager) -> (bool, usize)
{
        
    let mut new_offset = offset;
    let known_padding: [u8; 3] = [0x00, 0xCC, 0x90];
    let address_size = match analysis.xi.mode
    {
        Mode::Mode16=>2,
        Mode::Mode32=>4,
        Mode::Mode64=>8,
        _=>4,
    };
    let start = offset-analysis.base;
    let region = mem_manager.get_image_by_type(MemoryType::Image);
    let desired_end = start.checked_add(address_size)
        .unwrap_or(std::usize::MAX);
    let end = std::cmp::min(desired_end, region.len());

    let expected_padding_size = end - start;

    if expected_padding_size == 0 {
        return (false, ((start / address_size) + 1) * address_size)
    }

    let tail_slice = &region[start..end];

    for padding in known_padding.iter()
    {
        if *tail_slice == *vec![*padding; expected_padding_size]
        {
	    	let code_start = analysis.base + analysis.header.base_of_code as usize;
	    	let x = offset - code_start;
	    	let mut y = (x / address_size) * address_size;
	    	if y < x {
	    		y = y + address_size;
	    		new_offset = y + code_start;
	    	}
	    	return (true, new_offset);
	    }
    }
    return (false, new_offset);
}

pub fn analyze_datax86(
    offset: usize, 
    analysis: &mut Analysisx86, 
    mem_manager: &mut MemoryManager,
    state: &mut Statex86,
    queue: &mut VecDeque<Statex86>)-> AnalysisResult
{
    //
    let start = offset;
    let address_size = match analysis.xi.mode
    {
        Mode::Mode16=>2,
        Mode::Mode32=>4,
        Mode::Mode64=>8,
        _=>4,
    };

    let value = mem_manager.read(start, address_size, analysis);

    match mem_manager.get_mem_type(value as usize)
    {
        // Is a valid address
        MemoryType::Image=>{
            // 1) Check for function header ->
            //       a) add newfunction
            //       b) send to analysis queue as new current function
            //       c) db offset <ADDRESS> ; FUNC_<ADDRESS>
            //       d) continue
            if check_for_function_header(
                value as usize, 
                address_size,
                analysis,
                mem_manager)
            {
                let func_name = match analysis.add_func(
                    0,
                    offset as u64,
                    0,
                    0, 
                    value as u64, 
                    MemoryType::Image,
                    false)
                {
                    Some(f)=>f,
                    None=>String::new(),
                };
                let mut instructions: Instruction<X86Detail>;
                instructions = Instruction::new();
                instructions.address = offset as u64;
                instructions.offset = offset as u64;
                let bytes = transmute_integer_to_vec(value as usize, address_size);
                for (i, value) in bytes.iter().enumerate()
                {
                    instructions.bytes[i] = *value;
                }
                instructions.mnemonic = String::from("dd");
                match address_size
                {
                    2=>instructions.op_str = format!("offset 0x{:x}", value as u16),
                    4=>instructions.op_str = format!("offset 0x{:x}", value as u32),
                    8=>instructions.op_str = format!("offset 0x{:x}", value as u64),
                    _=>{},
                }
                instructions.size = address_size;
                let mut valid_instr = InstructionInfo
                  {
                    instr: instructions,
                    detail: Vec::new(),
                };
                valid_instr.detail.push(DetailInfo{op_index: 0, contents: func_name});
                analysis.instr_info.insert(offset as u64, valid_instr);
                let new_analysis: Statex86 = Statex86 
                {
                    offset: value as usize,
                    cpu: state.cpu.clone(), 
                    stack: Vec::new(),
                    current_function_addr: value as u64,
                    emulation_enabled: state.emulation_enabled,
                    loop_state: state.loop_state.clone(),
                    analysis_type: AnalysisType::Code,
                };
                queue.push_front(new_analysis);
                
                let mut new_data_analysis = state.clone();
                new_data_analysis.offset = offset + address_size;
                queue.push_back(new_data_analysis);
                return AnalysisResult::End;
            }
            // 2) if not db offset <ADDRESS>, fill bytes
            //       a) add address as bytes db <BYTES>, fill bytes
            //       b) continue
            else {
                let mut instructions: Instruction<X86Detail>;
                instructions = Instruction::new();
                instructions.address = offset as u64;
                instructions.offset = offset as u64;
                let bytes = transmute_integer_to_vec(value as usize, address_size);
                for (i, value) in bytes.iter().enumerate()
                {
                    instructions.bytes[i] = *value;
                }
                instructions.mnemonic = String::from("dd");
                match address_size
                {
                    2=>instructions.op_str = format!("offset 0x{:x}", value as u16),
                    4=>instructions.op_str = format!("offset 0x{:x}", value as u32),
                    8=>instructions.op_str = format!("offset 0x{:x}", value as u64),
                    _=>{},
                }
                instructions.size = address_size;
                let mut valid_instr = InstructionInfo
                  {
                    instr: instructions,
                    detail: Vec::new(),
                };

                analysis.instr_info.insert(offset as u64, valid_instr);
                let mut new_data_analysis = state.clone();
                new_data_analysis.offset = offset + address_size;
                queue.push_back(new_data_analysis);
                return AnalysisResult::End;
            }
        },
        MemoryType::Import =>{
            let func_name = match analysis.add_func(
                0,
                offset as u64,
                0,
                0, 
                value as u64, 
                MemoryType::Import,
                false)
            {
                Some(f)=>f,
                None=>String::new(),
            };
            let mut instructions: Instruction<X86Detail>;
            instructions = Instruction::new();
            instructions.address = offset as u64;
            instructions.offset = offset as u64;
            let bytes = transmute_integer_to_vec(value as usize, address_size);
            for (i, value) in bytes.iter().enumerate()
            {
                instructions.bytes[i] = *value;
            }
            instructions.mnemonic = String::from("dd");
            match address_size
            {
                2=>instructions.op_str = format!("offset 0x{:x}", value as u16),
                4=>instructions.op_str = format!("offset 0x{:x}", value as u32),
                8=>instructions.op_str = format!("offset 0x{:x}", value as u64),
                _=>{},
            }
            instructions.size = address_size;
            let mut valid_instr = InstructionInfo
              {
                instr: instructions,
                detail: Vec::new(),
            };
            valid_instr.detail.push(DetailInfo{op_index: 0, contents: func_name});
            analysis.instr_info.insert(offset as u64, valid_instr);
            let mut new_data_analysis = state.clone();
            new_data_analysis.offset = offset + address_size;
            queue.push_back(new_data_analysis);
            return AnalysisResult::End;
        },
        // Not a valid address
        _=>{
            // 1) Check for function header
            //       a) add newfunction
            //       b) send to analysis queue as new current function
            //       c) Break
            if check_for_function_header(
                start, 
                address_size,
                analysis,
                mem_manager)
            {
                analysis.add_func(0, 0, 0, 0, 
                    start as u64, 
                    MemoryType::Image,
                    false);
                let new_analysis: Statex86 = Statex86 
                {
                    offset: start,
                    cpu: state.cpu.clone(), 
                    stack: Vec::new(),
                    current_function_addr: start as u64,
                    emulation_enabled: state.emulation_enabled,
                    loop_state: state.loop_state.clone(),
                    analysis_type: AnalysisType::Code,
                };
                queue.push_front(new_analysis);
                return AnalysisResult::End;
            } else if check_for_jump(
                start, 
                address_size,
                analysis,
                mem_manager)
            {
                let new_analysis: Statex86 = Statex86 
                {
                    offset: start,
                    cpu: state.cpu.clone(), 
                    stack: Vec::new(),
                    current_function_addr: 0,
                    emulation_enabled: state.emulation_enabled,
                    loop_state: state.loop_state.clone(),
                    analysis_type: AnalysisType::Code,
                };
                queue.push_front(new_analysis);
                return AnalysisResult::End;
            }
            // 2) if not, db <BYTES>, fill bytes 
            else {
                let mut instructions: Instruction<X86Detail>;
                instructions = Instruction::new();
                instructions.address = offset as u64;
                instructions.offset = offset as u64;
                let bytes = transmute_integer_to_vec(value as usize, address_size);
                for (i, value) in bytes.iter().enumerate()
                {
                    instructions.bytes[i] = *value;
                }
                instructions.mnemonic = String::from("dd");
                match address_size
                {
                    2=>instructions.op_str = format!("0x{:x}", value as u16),
                    4=>instructions.op_str = format!("0x{:x}", value as u32),
                    8=>instructions.op_str = format!("0x{:x}", value as u64),
                    _=>{},
                }
                instructions.size = address_size;
                let mut _valid_instr = InstructionInfo
                  {
                    instr: instructions,
                    detail: Vec::new(),
                };
                analysis.instr_info.insert(offset as u64, _valid_instr);
            }
        },
    }
    return AnalysisResult::Continue;
}

fn check_for_function_header(
    offset: usize, 
    address_size: usize,
    analysis: &mut Analysisx86, 
    mem_manager: &mut MemoryManager) -> bool
{
    let max_length = mem_manager.get_image_by_type(MemoryType::Image).len();
    let start: isize = (offset as isize) - (analysis.base as isize);
    if start < 0
    {
        return false;
    }
    let mut end = (start as usize) + MAX_SIGNATURE_SIZE;
    if end > max_length
    {
        end = max_length;
    }
    match address_size
    {
        4=>{
            let results = analysis.sig_analyzer.match_bytes(&mem_manager.get_image_by_type(MemoryType::Image)[(start as usize)..end]);
            match results.get(&String::from("_standard_func_header"))
            {
                Some(result)=>{
                    if result.contains(&0usize)
                    {
                        return true;
                    }
                }
                None=>{},
            }
            match results.get(&String::from("_non_standard_func_header"))
            {
                Some(result)=>{
                    if result.contains(&0usize)
                    {
                        return true;
                    }
                }
                None=>{},
            }
        },
        8=>{
            let results = analysis.sig_analyzer.match_bytes(&mem_manager.get_image_by_type(MemoryType::Image)[(start as usize)..end]);
            match results.get(&String::from("_standard_func_header"))
            {
                Some(result)=>{
                    if result.contains(&0usize)
                    {
                        return true;
                    }
                }
                None=>{},
            }
        },
        _=>{},
    }
    return false;
}

fn check_for_jump(
    offset: usize, 
    address_size: usize,
    analysis: &mut Analysisx86, 
    mem_manager: &mut MemoryManager) -> bool
{
    let max_length = mem_manager.get_image_by_type(MemoryType::Image).len();
    let start: isize = (offset as isize) - (analysis.base as isize);
    if start < 0
    {
        return false;
    }
    let mut end = (start as usize) + MAX_SIGNATURE_SIZE;
    if end > max_length
    {
        end = max_length;
    }
    match address_size
    {
        4=>{
            let results = analysis.sig_analyzer.match_bytes(&mem_manager.get_image_by_type(MemoryType::Image)[(start as usize)..end]);
            match results.get(&String::from("_possible_function_jump"))
            {
                Some(result)=>{
                    if result.contains(&0usize)
                    {
                        return true;
                    }
                }
                None=>{},
            }
        },
        8=>{
            let results = analysis.sig_analyzer.match_bytes(&mem_manager.get_image_by_type(MemoryType::Image)[(start as usize)..end]);
            match results.get(&String::from("_possible_function_jump"))
            {
                Some(result)=>{
                    if result.contains(&0usize)
                    {
                        return true;
                    }
                }
                None=>{},
            }
        },
        _=>{},
    }
    return false;
}

pub fn scan_for_function_blocks(
    analysis: &mut Analysisx86,
    mem_manager: &mut MemoryManager)
{
    let flirt = analysis.sig_analyzer.flirt_match(&mem_manager.get_image_by_type(MemoryType::Image));
    debug!("EXPERIMENTAL FLIRT SIG MATCHES\n{:?}",flirt);
    if flirt.len() == 0 && analysis.functions.len() == 0
    {
        return;
    }

    for (key, entry) in flirt
    {
        match analysis.sig_analyzer.flirts.get(&key)
        {
            Some(sig)=>{
                if sig.references.len() > 0
                {
                    for reference in sig.references.iter()
                    {
                        let offset = (reference.offset + entry[0] + analysis.base) as u64;
                        debug!("scan_for_function_blocks: name: {} offset: 0x{:x}", reference.name, offset);
                        // Rename Function
                        for func in analysis.functions.iter_mut()
                        {
                            if func.xrefs.get(&offset).is_some()                                            
                            {
                                func.name = reference.name.clone();
                            }
                        }
                        // Add comment in instr_info
                        match analysis.instr_info.get_mut(&offset)
                        {
                            Some(instr_info)=>{
                                instr_info.detail = vec![DetailInfo
                                {
                                    op_index: 0,
                                    contents: reference.name.clone(),
                                }];
                            },
                            None=>{},
                        }
                    }
                }
            },
            None=>{},
        }
    }
}

pub fn rename_indirect_calls(
    analysis: &mut Analysisx86)
{
    let mut update_functions: BTreeMap<u64, String> = BTreeMap::new();
    for func in analysis.functions.iter()
    {
        if func.mem_type == MemoryType::Import
        {
            for xref in func.xrefs.iter()
            {
                for pfunc in analysis.functions.iter()
                {
                    if *xref == pfunc.address
                    {
                        update_functions.insert(pfunc.address, func.name.clone());
                        update_functions.insert(func.address, format!("__imp_{}", func.name));
                    }
                }
            }
        }
    }

    for func in analysis.functions.iter_mut()
    {
        match update_functions.get(&func.address)
        {
            Some(f)=>{
                if f.contains("__imp_")
                {
                    func.name = f.clone();
                } 
                else
                {
                    let new_name: Vec<_> = f.split('!').collect();
                    if new_name.len() > 1
                    {
                        func.name = new_name[1].to_string();
                    } else {
                        func.name = f.clone();
                    }
                }
                
                // Update all references
                for xref in func.xrefs.iter()
                {
                    match analysis.instr_info.get_mut(&xref)
                    {
                        Some(instr_info)=>{
                            instr_info.detail = vec![DetailInfo
                            {
                                op_index: 0,
                                contents: func.name.clone(),
                            }];
                        },
                        None=>{},
                    }
                }
            },
            _=>{},
        }
    }
}

