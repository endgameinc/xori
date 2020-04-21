//dump_functions.rs
extern crate colored;
extern crate num;
extern crate nom;
extern crate argparse;
extern crate xori;
extern crate memmap;
extern crate serde_json;
extern crate uuid;
use colored::*;

use xori::analysis::analyze::FuncInfo;
use xori::arch::x86::analyzex86::InstructionInfo;
use std::collections::BTreeMap;

use argparse::{ArgumentParser, StoreTrue, Store};
use std::path::Path;

#[derive(Debug,Clone,PartialEq)]
enum BlockType
{
	Start,
	Begin,
	End,
	Return,
	Both,
}
fn print_function(function: &FuncInfo, _disasm: &BTreeMap<u64, InstructionInfo>)
{
	// Build blocks
	let keys: Vec<_> = _disasm.keys().cloned().collect();
	let mut blocks: BTreeMap<u64, BlockType> = BTreeMap::new();

	blocks.insert(function.address, BlockType::Start);	

	if function.returns.len() > 0
	{
		for ret in function.returns.iter()
		{
			if blocks.contains_key(ret)
			{
				let is_begin = match blocks.get(ret)
				{
					Some(btype)=>{
						match btype{
							BlockType::Start | BlockType::Begin =>true,
							_=>false,
						}
					}
					None=>false,
				};
				if is_begin
				{
					blocks.insert(*ret, BlockType::Both);
				}

			} else {
			   blocks.insert(*ret, BlockType::Return);
			}
		}
	}

	if function.jumps.len()>0
	{
		for (key, jump) in function.jumps.iter()
		{
			println!("0x{:x} Left: 0x{:x} right: 0x{:x}",key, jump.left, jump.right );

			if blocks.contains_key(key)
			{
				let is_begin = match blocks.get(key)
				{
					Some(btype)=>{
						match btype{
							BlockType::Start | BlockType::Begin =>true,
							_=>false,
						}
					}
					None=>false,
				};
				if is_begin
				{
					blocks.insert(*key, BlockType::Both);
				}

			} else {
			   blocks.insert(*key, BlockType::End);
			}

			if jump.left != 0 {
				if blocks.contains_key(&(jump.left as u64))
				{
					let is_end = match blocks.get(&(jump.left as u64))
					{
						Some(btype)=>{
							match btype{
								BlockType::End | BlockType::Return =>true,
								_=>false,
							}
						}
						None=>false,
					};
					if is_end
					{
						blocks.insert(jump.left as u64, BlockType::Both);
					}

				} else {
				   blocks.insert(jump.left as u64, BlockType::Begin);
				}
				
			}
			if jump.right != 0
			{
				if blocks.contains_key(&(jump.right as u64))
				{
					let is_begin = match blocks.get(&(jump.right as u64))
					{
						Some(btype)=>{
							match btype{
								BlockType::End | BlockType::Return =>true,
								_=>false,
							}
						}
						None=>false,
					};
					if is_begin
					{
						blocks.insert(jump.right as u64, BlockType::Both);
					}

				} else {
				   blocks.insert(jump.right as u64, BlockType::Begin);
				   match keys.binary_search(&(jump.right as u64))
				   {
				   	Ok(index)=>{
				   		if index != 0{
				   			let previous_index = index-1;
				   			let previous_instr = keys[previous_index];
				   			if blocks.contains_key(&previous_instr)
				   			{
				   				let is_begin = match blocks.get(&previous_instr)
				   				{
				   					Some(btype)=>{
				   						match btype{
				   							BlockType::Start | BlockType::Begin =>true,
				   							_=>false,
				   						}
				   					}
				   					None=>false,
				   				};
				   				if is_begin
				   				{
				   					blocks.insert(previous_instr, BlockType::Both);
				   				}

				   			} else {
				   			   blocks.insert(previous_instr, BlockType::End);
				   			}
				   		}
				   	},
				   	_=>{}
				   }
				}
				
			}
		}
	}

	for (key, val) in blocks.iter()
	{
		println!("0x{:x} {:?}", key, val );
	}
	

	let bkeys: Vec<_> = blocks.keys().cloned().collect();
    let mut pairs: Vec<(u64, u64)> = Vec::new();
	let mut i = 0;
	while i < bkeys.len()
	{
		let mut _start: u64 = 0;
		let mut _end: u64 = 0;

		match blocks.get(&bkeys[i])
		{
			Some(btype)=>{
				match btype{
					BlockType::Both=>{
						_start = bkeys[i];
						_end = bkeys[i];
						i+=1;
						if _start != 0 && _end != 0{
							pairs.push((_start, _end));
						}
						continue;
					},
					BlockType::Start | BlockType::Begin =>{
						_start = bkeys[i];
						//print!("0x{:x} {:?} ", bkeys[i],  btype);
						if i+1 >= bkeys.len()
						{
							i+=1;
							continue;
						}
						_end = match blocks.get(&bkeys[i+1])
						{
							Some(btype1)=>{
								//println!("0x{:x} {:?}", bkeys[i+1],  btype1);
								match btype1{
									BlockType::End | BlockType::Return => bkeys[i+1],
									BlockType::Both | BlockType::Start =>{
										i+=1;
										continue;
									}
									_=>0,
								}
							}
							_=>0,
						};
						if _start != 0 && _end != 0{
							pairs.push((_start, _end));
						}
						i+=2;
						continue;
					},
					BlockType::End=>{
						i+=1;
						continue;
					},
					_=>{},
				}
			}
			_=>{},
		};
		i+=1;
	}


	println!("Block Count: {}", pairs.len());
	
	for (start, end) in pairs.iter()
	{
		//println!("start: 0x{:x}, end: 0x{:x}", start, end);
		for (_addr, instr) in _disasm.range(start..&(end+1))
		{
			let addr: String = format!("0x{:x}", instr.instr.address);
	        let mut detail: String = String::new();
	        if instr.detail.len() > 0 {
	            for d in instr.detail.iter()
	            {
	                if !d.contents.is_empty(){
	                    detail = format!("{}; {}", detail, d.contents);
	                } 
	            }
	              
	        }
	        println!("{:16} {} {} {}", 
	            addr.yellow(),
	            instr.instr.mnemonic,
	            instr.instr.op_str,
	            detail.green());
		}
		println!("---------");
	}
	
}
fn main() 
{
    let mut functions: String = String::new();
    let mut disassembly: String = String::new();
    let mut function_address: String = String::new();
    let mut show: bool = false;

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("prints the disassembly for a particular function");
        ap.refer(&mut functions)
        .add_option(
            &["--functions", "-f"],
            Store,
            "Path of the <UUID>_functions.json")
        .required();

        ap.refer(&mut disassembly)
        .add_option(
            &["--disasm", "-d"],
            Store,
            "Path of the <UUID>_disasm.json")
        .required();

        ap.refer(&mut function_address).add_option(
            &["--address", "-a"],
            Store,
            "display the disassembly of function addess. If address is 0x12345 then input is 12345.",
        );
        ap.refer(&mut show).add_option(
            &["--list", "-l"],
             StoreTrue,
            "List all functions",
        );
        ap.parse_args_or_exit();
    }

    // Verify input path
    let path = Path::new(&functions);
    if !path.exists() || !path.is_file(){
        eprintln!("error: file does not exist");
        std::process::exit(1);
    }

    let mut disasm_info: BTreeMap<u64, InstructionInfo> = BTreeMap::new();
    let disasm_path = Path::new(&disassembly);
    if disasm_path.exists()
    {
        let file = ::std::fs::File::open(disasm_path)
        	.expect("failed to open the file"); 

	    match serde_json::from_reader(file){
	    	Ok(s)=>{
	    		disasm_info = s;
	    	},
	    	_=>{},
	    }
    }
    else {
        panic!("error: disasm json file does not exist, using default configurations.");
    }

    let mut function_info: Vec<FuncInfo> = Vec::new();
    let func_path = Path::new(&functions);
    if func_path.exists()
    {
        let file = ::std::fs::File::open(func_path)
        	.expect("failed to open the file"); 
	    match serde_json::from_reader(file){
	    	Ok(s)=>{
	    		function_info = s;
	    	},
	    	_=>{},
	    }
    }
    else {
        panic!("error: disasm json file does not exist, using default configurations.");
    }

    let target_addr = match u64::from_str_radix(&function_address, 16){
	    Ok(s)=>{
    		s
    	},
    	_=>0,
	};

    if show{
    	function_info.sort_by_key(|k| k.address);
    	for func in function_info.iter()
    	{
    		println!("address: {:x} mem_type: {:?} func_name: {}", func.address, func.mem_type, func.name);
    	}

    } else if target_addr!=0{

    	for func in function_info.iter()
    	{
    		if target_addr == func.address
    		{
    			println!("address: {:x} mem_type: {:?} func_name: {}", func.address, func.mem_type, func.name);
    			print_function(&func, &disasm_info);
    		}
    	}
    }
}
