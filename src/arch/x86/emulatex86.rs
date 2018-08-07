//emulatex86.rs
use arch::x86::displayx86::*;
use arch::x86::archx86::*;
use arch::x86::analyzex86::*;
use arch::x86::cpux86::*;
use arch::x86::registersx86::*;
use disasm::*;
use num::PrimInt;

#[derive(Debug,Clone,PartialEq)]
enum LoopType
{
    Invalid,
    Branch,
    Loop,
    Jump,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoopEntry
{
    pub offset: u64,
    pub destination: u64,
    pub loop_count: usize,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ForwardLoopEntry
{
    pub offset: u64,
    pub forward_addr: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LoopState
{
    pub max_loops: usize,
    pub is_loop: bool,
    pub forward_addr: Vec<ForwardLoopEntry>,
    pub loop_tracker: Vec<LoopEntry>
}

macro_rules! get_operand {
    (index: $i:expr; $instr:expr; $analysis:expr; $state:expr; $mem:expr) => {
            match $instr.instr.detail.operands()[$i].op_type{
                InstrOpTypex86::Reg=>{
                    let _size = $instr.instr.detail.operands()[$i].size as usize;
                    $state.cpu.get_register(
                    &$instr.instr.detail.operands()[$i].reg, $instr.instr.size)
                },
                InstrOpTypex86::Imm=>{
                    let _size = $instr.instr.detail.operands()[$i].size as usize;
                    $instr.instr.detail.operands()[$i].imm
                },
                InstrOpTypex86::Mem=>{ 
                    let _size = $instr.instr.detail.operands()[$i].size as usize;
                    let (_address, _value) = get_memory_operand(
                        &$instr.instr.detail.operands()[$i].mem,
                        $instr.instr.size,
                        _size,
                        $analysis,
                        $mem,
                        $state);
                    _value
                },
                _=>{
                    debug!("unknown operand");
                    0
                },
            };
    }
}

macro_rules! set_operand {
    (value: $v:expr; index: $i:expr; $instr:expr; $analysis:expr; $state:expr; $mem:expr) => {
            match $instr.instr.detail.operands()[$i].op_type{
                InstrOpTypex86::Reg=>{
                    $state.cpu.set_register(
                        &$instr.instr.detail.operands()[$i].reg, 
                        $v);
                },
                InstrOpTypex86::Imm=>{},
                InstrOpTypex86::Mem=>{
                    let _size = $instr.instr.detail.operands()[$i].size as usize;
                    set_memory_operand(
                        &$instr.instr.detail.operands()[$i].mem,
                        $v,
                        $instr.instr.size,
                        _size,
                        $analysis,
                        $mem,
                        $state);
                },
                _=>{},
            }
    }
}

fn get_memory_operand(
    _mem: &InstrMemx86,
    _instr_size: usize, 
    _value_size: usize,
    _analysis: &mut Analysisx86,
    _mem_manager: &mut MemoryManager,
    _state: &mut Statex86)->(i64, i64)
{
    let mut _segment_offset: i64 = 0;
    let mut _base: i64 = 0;
    let mut _index: i64 = 0;
    let mut _scale: i64 = 0;
    let mut _address: i64 = 0;
    // if in a specific segement
    if _mem.segment != 0 {
        _segment_offset = _state.cpu.get_register(&(_mem.segment as u8), _instr_size);
    }       
    if _mem.base != 0 {
        _base = _state.cpu.get_register(&(_mem.base as u8), _instr_size);
    }
    if _mem.index != 0 {
        _index = _state.cpu.get_register(&(_mem.index as u8), _instr_size);
    }
    
    if _mem.scale < 2 {
        _address =  _segment_offset.wrapping_add(_base).wrapping_add(_index).wrapping_add(_mem.displacement);
    }
    else{
        match _state.cpu.address_size{
            2=>{
                // handling overflow error
                let index_offset = (_index as i16).wrapping_mul(_mem.scale as i16);
                _address = (_segment_offset as i16).wrapping_add(_base as i16).wrapping_add(index_offset).wrapping_add(_mem.displacement as i16) as i64;
            },
            4=>{
                let index_offset = (_index as i32).wrapping_mul(_mem.scale as i32);
                _address = (_segment_offset as i32).wrapping_add(_base as i32).wrapping_add(index_offset).wrapping_add(_mem.displacement as i32) as i64; 
            },
            _=>{
                let index_offset = (_index as i64).wrapping_mul(_mem.scale as i64);
                _address = _segment_offset.wrapping_add(_base).wrapping_add(index_offset).wrapping_add(_mem.displacement);
            },
        }
    }
    let (is_stack, _base_addr, _bounds_size) = _mem_manager.is_stack(_address as usize);
    if is_stack
    {
        let mem_address = _state.stack_read(
                                    _address, 
                                    _value_size);
        return (_address, mem_address);
    } else {
        let mem_address = _mem_manager.read(
            _address as usize,
            _value_size,
            _analysis,
            );
        return (_address, mem_address);
    }
}

fn set_memory_operand(
    _mem: &InstrMemx86,
    _value: i64,
    _instr_size: usize,
    _value_size: usize,
    _analysis: &mut Analysisx86,
    _mem_manager: &mut MemoryManager,
    _state: &mut Statex86) -> u64
{
    let mut _segment_offset: i64 = 0;
    let mut _base: i64 = 0;
    let mut _index: i64 = 0;
    let mut _scale: i64 = 0;
    let mut _address: u64 = 0;
    // if in a specific segement
    if _mem.segment != 0 {
        _segment_offset = _state.cpu.get_register(&(_mem.segment as u8), _instr_size);
    } 
        
    if _mem.base != 0 {
        _base = _state.cpu.get_register(&(_mem.base as u8), _instr_size);
    }
    if _mem.index != 0 {
        _index = _state.cpu.get_register(&(_mem.index as u8), _instr_size);
    }

    if _mem.scale < 2 {
        _address = _segment_offset.wrapping_add(_base).wrapping_add(_index).wrapping_add(_mem.displacement) as u64;
    }
    else{
        match _state.cpu.address_size{
            2=>{
                // handling overflow error
                let index_offset = (_index as i16).wrapping_mul(_mem.scale as i16);
                _address = (_segment_offset as i16).wrapping_add(_base as i16).wrapping_add(index_offset).wrapping_add(_mem.displacement as i16) as u64;  
            },
            4=>{
                let index_offset = (_index as i32).wrapping_mul(_mem.scale as i32);
                _address = (_segment_offset as i32).wrapping_add(_base as i32).wrapping_add(index_offset).wrapping_add(_mem.displacement as i32) as u64; 
            },
            _=>{
                let index_offset = (_index as i64).wrapping_mul(_mem.scale as i64);
                _address = _segment_offset.wrapping_add(_base).wrapping_add(index_offset).wrapping_add(_mem.displacement) as u64; 
            },
        }
    }
    
    let (is_stack, _base_addr, bounds_size) = _mem_manager.is_stack(_address as usize);
    if is_stack
    {
        _state.stack_write(
            _address, 
            _value, 
            _value_size, 
            bounds_size);
    } else {
        _mem_manager.write(
            _address as usize, 
            _value as u64, 
            _value_size, 
            );
    }        
    return _address;
}

fn set_all_flags<T: PrimInt>(
    v: T,
    _is_overflow: FlagDefined,
    _auxillary: FlagDefined,
    _carry: FlagDefined,
    _state: &mut Statex86)
{
    if v < T::from(0).unwrap()
    {
        _state.cpu.set_flag(&EFlags::Sign, 1);
        _state.cpu.set_flag(&EFlags::Zero, 0);
    } 
    else if v == T::from(0).unwrap() {
        _state.cpu.set_flag(&EFlags::Sign, 0);
        _state.cpu.set_flag(&EFlags::Zero, 1);
    } else {
        _state.cpu.set_flag(&EFlags::Sign, 0);
        _state.cpu.set_flag(&EFlags::Zero, 0);
    }

    match _carry
    {
        FlagDefined::Set=>{
            _state.cpu.set_flag(&EFlags::Carry, 1);
        },
        FlagDefined::Unset=>{
            _state.cpu.set_flag(&EFlags::Carry, 0);
        },
        FlagDefined::Undefined=>{},
    }

    match _is_overflow
    {
        FlagDefined::Set=>{
            _state.cpu.set_flag(&EFlags::Overflow, 1);
        },
        FlagDefined::Unset=>{
            _state.cpu.set_flag(&EFlags::Overflow, 0);
        },
        FlagDefined::Undefined=>{},
    }
    let int_size = ::std::mem::size_of::<T>();
    let parity = match int_size {
        1=>v,
        _=>v & T::from(0xFF).unwrap(),
    }; 

    if (parity.count_ones() % 2) == 0 //is even # of ones
    {
        _state.cpu.set_flag(&EFlags::Parity, 1);
    } else {
        _state.cpu.set_flag(&EFlags::Parity, 0);
    }

    match _auxillary
    {
        FlagDefined::Set=>{
            _state.cpu.set_flag(&EFlags::Auxiliary, 1);
        },
        FlagDefined::Unset=>{
            _state.cpu.set_flag(&EFlags::Auxiliary, 0);
        },
        FlagDefined::Undefined=>{},
    }
}

fn check_forward_loop_exists(
    _offset: &u64,
    _right_destination: &mut i64,
    _branch_is_taken: &mut bool,
    _state: &Statex86) -> bool
{
    for (_i, loop_entry) in _state.loop_state.loop_tracker.iter().enumerate()
    {
        if loop_entry.offset == *_offset
        {
            return true;
        }
    }
    return false;
}

fn check_forward_loop_counter(
    _offset: &u64,
    _right_destination: &mut i64,
    _branch_is_taken: &mut bool,
    _state: &mut Statex86) -> (bool, Option<usize>)
{
    for (i, loop_entry) in _state.loop_state.loop_tracker.iter_mut().enumerate()
    {
        if loop_entry.offset == *_offset && loop_entry.enabled
        {
            if loop_entry.loop_count+1 > _state.loop_state.max_loops
            {   
                // Jump to be removed
                *_branch_is_taken = true;
                return (true, Some(i));
            } else if *_branch_is_taken {
            	loop_entry.loop_count=0;
                return (true, None);

            } else if !*_branch_is_taken{
                loop_entry.loop_count+=1;
                return (true, None);
            }
        } else if loop_entry.offset == *_offset && !loop_entry.enabled {
            *_branch_is_taken = true;
            return (true, None);
        }
    }
    return (false, None);
}

fn check_backward_loop_exists(
    _offset: &u64,
    _right_destination: &mut i64,
    _branch_is_taken: &mut bool,
    _state: &mut Statex86) -> (bool, Option<usize>)
{
    for (i, loop_entry) in _state.loop_state.loop_tracker.iter_mut().enumerate()
    {
        if loop_entry.offset == *_offset && loop_entry.enabled
        {
            //debug!("\tJump is found at 0x{:x} with count {}", _offset, loop_entry.loop_count);
            if loop_entry.loop_count+1 > _state.loop_state.max_loops
            {
                *_branch_is_taken = false;
                //debug!("\tJump is removed at 0x{:x} with count {}", _offset, loop_entry.loop_count+1);
                return (true, Some(i));
            } else if *_branch_is_taken {
                loop_entry.loop_count+=1;
                //debug!("\tJump is taken at 0x{:x} -> 0x{:x} count {}", _offset, _right_destination, loop_entry.loop_count);
                return (true, None);
            } else if !*_branch_is_taken{
            	loop_entry.loop_count=0;
                //debug!("\tJump is NOT taken at 0x{:x}", _offset);
                return (true, None);
            }
        } else if loop_entry.offset == *_offset && !loop_entry.enabled {
            *_branch_is_taken = false;
            return (true, None);
        }
    }
    return (false, None);
}

fn remove_loop_entry(loop_entry: Option<usize>, _state: &mut Statex86)
{
    match loop_entry
    {
        Some(lentry)=>{
            debug!("[REMOVED] 0x{:x}", _state.loop_state.loop_tracker[lentry].offset);
            _state.loop_state.loop_tracker[lentry].enabled = false;
        },
        None=>{}       
    }
}

fn propogate_loop(
    _loop_type: &LoopType,
    _offset: &u64,
    _next_instruction: &u64,
    _branch_is_taken: &mut bool,
    _left_destination: &mut i64,
    _right_destination: &mut i64,
    _mem_manager: &mut MemoryManager,
    _state: &mut Statex86)
{
    //debug!("propogate_loop");
    /* Determine if loop:
       1) must be a conditional jump, 
       2) a comparison intruction precedes the jump by 3 instructions
       3) an jump destination must be less than the current instruction
          and in the same memory binary
    */
    let dest_mem_type = _mem_manager.get_mem_type(*_right_destination as usize);
    let offset_mem_type = _mem_manager.get_mem_type(*_offset as usize);
    if dest_mem_type != offset_mem_type 
    {
        debug!("jump is not in the same memory space");
        return;
    }
    // identify loop
    match *_loop_type 
    {
        // backward loops
        LoopType::Branch=>{
            if (*_right_destination as u64) < *_offset
            {
                debug!("[BACKWARD] 0x{:x}", _offset);
                
                /* 1) if this is a valid loop and branch is taken
                      then populate the _jmp_instruction, else
                      make the _jmp_instruction = 0
                   2) check if the offset already exists in the loop_tracker, else
                   3) if the loop_count has not exited and has reached
                      the maximum loops allowed defined by the "loop_default_case"
                */
                let (loop_exists, loop_entry) = check_backward_loop_exists(
                    _offset, 
                    _right_destination, 
                    _branch_is_taken, 
                    _state);
 
                if !loop_exists && *_branch_is_taken
                {
                    _state.loop_state.loop_tracker.push(
                        LoopEntry{
                            offset: *_offset,
                            destination: *_right_destination as u64,
                            loop_count: 1,
                            enabled: true,
                        });
                    _state.loop_state.is_loop = true;
                    *_left_destination = 0;
                } else if loop_exists {
                    remove_loop_entry(
                    loop_entry,
                    _state,
                    );
                    if *_branch_is_taken {
                        *_left_destination = 0;
                    }
                }  
                if !*_branch_is_taken
                {
                    *_right_destination = 0;
                    _state.loop_state.is_loop = false;
                }             
            }
            // forward loop start
            else if (*_right_destination as u64) > *_offset
            {
                let (_loop_exists, _loop_entry) = check_forward_loop_counter(
                    _offset, 
                    _right_destination, 
                    _branch_is_taken, 
                    _state);

                if _loop_exists{
                    remove_loop_entry(
                        _loop_entry,
                        _state,
                        );
                    if *_branch_is_taken
                    {
                        *_left_destination = 0;
                        _state.loop_state.is_loop = false;
                    } else {
                        *_right_destination = 0;
                    }
                } else {
                    _state.loop_state.forward_addr.push(ForwardLoopEntry{
                        offset: *_offset,
                        forward_addr: *_right_destination as u64,
                    });
                    if *_branch_is_taken
                    {
                        *_left_destination = 0;
                    } else {
                        *_right_destination = 0;
                    }
                }
                if *_branch_is_taken
                {
                    *_left_destination = 0;
                    _state.loop_state.is_loop = false;
                } 
            }
        },
        LoopType::Loop=>{
            let (loop_exists, loop_entry) = check_backward_loop_exists(
                    _offset, 
                    _right_destination, 
                    _branch_is_taken, 
                    _state);

            if !loop_exists && *_branch_is_taken
            {
                _state.loop_state.loop_tracker.push(
                    LoopEntry{
                        offset: *_offset,
                        destination: *_right_destination as u64,
                        loop_count: 1,
                        enabled: true,
                    });
                _state.loop_state.is_loop = true;
                *_left_destination = 0;
            } else if loop_exists {
                remove_loop_entry(
                loop_entry,
                _state,
                );
                // Do not take left
                if *_branch_is_taken
                {
                    *_left_destination = 0;
                }
            }
            if !*_branch_is_taken
            {
                *_right_destination = 0;
                _state.loop_state.is_loop = false;
            }        
        },
        // handle forward loops
        LoopType::Jump=>{
            if (*_right_destination as u64) < *_offset
            {
                for (_i, forward_entry) in _state.loop_state.forward_addr.iter().enumerate()
                {
                    if forward_entry.forward_addr == *_next_instruction
                    {
                        let loop_exists = check_forward_loop_exists(
                                &forward_entry.offset, 
                                _right_destination, 
                                _branch_is_taken, 
                                _state);
                        if !loop_exists {
                            _state.loop_state.loop_tracker.push(
                                LoopEntry{
                                    offset: forward_entry.offset,
                                    destination: *_next_instruction as u64,
                                    loop_count: 1,
                                    enabled: true,
                                });
                            _state.loop_state.is_loop = true;
                        }
                        break;
                    }
                }
            }
        },
        _=>{
        },
    }
}

// EMULATED INSTRUCTIONS

fn addx86(size: usize, value1: i64, value2: i64, _state: &mut Statex86) -> i64
{
    let mut auxiliary = FlagDefined::Unset;
    if ((value1 & 0xF) + (value2 & 0xF)) & 0x10 > 0 {
        auxiliary = FlagDefined::Set;
    }

    let result: i64 = match size{
        1=>{
            let (temp, _carry) = (value1 as u8).overflowing_add(value2 as u8);
            let _is_overflow = match (value1 as i8).checked_add(value2 as i8){
                Some(_v)=>FlagDefined::Unset,
                None=>FlagDefined::Set,
            };
            let v = temp as i8;
            let _is_carry = match _carry{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };

            set_all_flags(v, _is_overflow, auxiliary, _is_carry, _state);
            temp as i64
        },
        2=>{
            let (temp, _carry) = (value1 as u16).overflowing_add(value2 as u16);
            let _is_overflow = match (value1 as i16).checked_add(value2 as i16){
                Some(_v)=>FlagDefined::Unset,
                None=>FlagDefined::Set,
            };
            let v = temp as i16;
            let _is_carry = match _carry{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };

            set_all_flags(v, _is_overflow, auxiliary, _is_carry, _state);
            temp as i64
        },
        4=>{
            let (temp, _carry) = (value1 as u32).overflowing_add(value2 as u32);
            let _is_overflow = match (value1 as i32).checked_add(value2 as i32){
                Some(_v)=>FlagDefined::Unset,
                None=>FlagDefined::Set,
            };
            let v = temp as i32;
            let _is_carry = match _carry{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };
            set_all_flags(v, _is_overflow, auxiliary, _is_carry, _state);
            temp as i64
        },
        _=>{
            let (temp, _carry) = (value1 as u64).overflowing_add(value2 as u64);
            let _is_overflow = match (value1 as i64).checked_add(value2 as i64){
                Some(_v)=>FlagDefined::Unset,
                None=>FlagDefined::Set,
            };
            let _is_carry = match _carry{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };
            set_all_flags(temp as i64, _is_overflow, auxiliary, _is_carry, _state);
            temp as i64
        },
    };
    return result;
}

fn subx86(size: usize, value1: i64, value2: i64, _state: &mut Statex86) -> i64
{
    let mut auxiliary = FlagDefined::Unset;
    if (value1 & 0xF) < (value2 & 0xF) {
        auxiliary = FlagDefined::Set;
    }

    let result: i64 = match size{
        1=>{
            let (temp, _carry) = (value1 as u8).overflowing_sub(value2 as u8);
            let _is_overflow = match (value1 as i8).checked_sub(value2 as i8){
                Some(_v)=>FlagDefined::Unset,
                None=>FlagDefined::Set,
            };
            let v = temp as i8;
            let _is_carry = match _carry{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };

            set_all_flags(v, _is_overflow, auxiliary, _is_carry, _state);
            temp as i64
        },
        2=>{
            let (temp, _carry) = (value1 as u16).overflowing_sub(value2 as u16);
            let _is_overflow = match (value1 as i16).checked_sub(value2 as i16){
                Some(_v)=>FlagDefined::Unset,
                None=>FlagDefined::Set,
            };
            let v = temp as i16;
            let _is_carry = match _carry{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };

            set_all_flags(v, _is_overflow, auxiliary, _is_carry, _state);
            temp as i64
        },
        4=>{
            let (temp, _carry) = (value1 as u32).overflowing_sub(value2 as u32);
            let _is_overflow = match (value1 as i32).checked_sub(value2 as i32){
                Some(_v)=>FlagDefined::Unset,
                None=>FlagDefined::Set,
            };
            let v = temp as i32;
            let _is_carry = match _carry{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };
            set_all_flags(v, _is_overflow, auxiliary, _is_carry, _state);
            temp as i64
        },
        _=>{
            let (temp, _carry) = (value1 as u64).overflowing_sub(value2 as u64);
            let _is_overflow = match (value1 as i64).checked_sub(value2 as i64){
                Some(_v)=>FlagDefined::Unset,
                None=>FlagDefined::Set,
            };
            let _is_carry = match _carry{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };
            set_all_flags(temp as i64, _is_overflow, auxiliary, _is_carry, _state);
            temp as i64
        },
    };
    return result;
}

fn mulx86(signed: bool, size: usize, value2: i64, _state: &mut Statex86)
{
    match size {
        1=>{
            let reg = _state.cpu.get_register(&(Registersx86::AL as u8), 0);

            let (temp, _is_overflow) = match signed
            {
                true=>{
                    let (temp, _carry) = (reg as i16).overflowing_mul(value2 as i16);
                    let check_overflow = (reg as i8).checked_mul(value2 as i8);
                    (temp as i8, check_overflow.is_some()) 
                },
                false=>{
                    let (temp, _carry) = (reg as u16).overflowing_mul(value2 as u16);
                    let check_overflow = (reg as u8).checked_mul(value2 as u8);
                    (temp as i8, check_overflow.is_some()) 
                },
            };

            let _is_carry = match _is_overflow{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };
            
            //Set Flags
            set_all_flags(temp as i64, _is_carry, FlagDefined::Undefined, _is_carry, _state);

            _state.cpu.set_register(&(Registersx86::AX as u8), temp as i64);
        },
        2=>{
            let reg = _state.cpu.get_register(&(Registersx86::AX as u8), 0);
            let (mut temp, _is_overflow) = match signed
            {
                true=>{
                    let (temp, _of) = (reg as i32).overflowing_mul(value2 as i32);
                    let check_overflow = (reg as i16).checked_mul(value2 as i16);
                    (temp as i16, check_overflow.is_some()) 
                },
                false=>{
                    let (temp, _of) = (reg as u32).overflowing_mul(value2 as u32);
                    let check_overflow = (reg as u16).checked_mul(value2 as u16);
                    (temp as i16, check_overflow.is_some()) 
                },
            };

            let _is_carry = match _is_overflow{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };
            
            //Set Flags
            set_all_flags(temp as i64, _is_carry, FlagDefined::Undefined, _is_carry, _state);
            _state.cpu.set_register(&(Registersx86::AX as u8), temp as i64);

            let higher_bits = (temp as u64 >> 16) & 0xFFFF;
            _state.cpu.set_register(&(Registersx86::DX as u8), higher_bits as i64);
        },
        4=>{
            let reg = _state.cpu.get_register(&(Registersx86::EAX as u8), 0);
            let (mut temp, _is_overflow) = match signed
            {
                true=>{
                    let (temp, _of) = (reg as i64).overflowing_mul(value2 as i64);
                    let check_overflow = (reg as i32).checked_mul(value2 as i32);
                    (temp as i32, check_overflow.is_some()) 
                },
                false=>{
                    let (temp, _of) = (reg as u64).overflowing_mul(value2 as u64);
                    let check_overflow = (reg as u32).checked_mul(value2 as u32);
                    (temp as i32, check_overflow.is_some()) 
                },
            };

            let _is_carry = match _is_overflow{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };
            
            //Set Flags
            set_all_flags(temp as i64, _is_carry, FlagDefined::Undefined, _is_carry, _state);

            _state.cpu.set_register(&(Registersx86::EAX as u8), temp as i64);
            let higher_bits = (temp as u64 >> 32) & 0xFFFFFFFF;
            _state.cpu.set_register(&(Registersx86::EDX as u8), higher_bits as i64);
        },
        _=>{
            let reg = _state.cpu.get_register(&(Registersx86::RAX as u8), 0);

            let (mut temp, _is_overflow) = match signed
            {
                true=>{
                    let (temp, _of) = (reg as i128).overflowing_mul(value2 as i128);
                    let check_overflow = (reg as i64).checked_mul(value2 as i64);
                    (temp as i64, check_overflow.is_some()) 
                },
                false=>{
                    let (temp, _of) = (reg as u128).overflowing_mul(value2 as u128);
                    let check_overflow = (reg as u64).checked_mul(value2 as u64);
                    (temp as i64, check_overflow.is_some()) 
                },
            };

             let _is_carry = match _is_overflow{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };
            
            //Set Flags
            set_all_flags(temp as i64, _is_carry, FlagDefined::Undefined, _is_carry, _state);

            _state.cpu.set_register(&(Registersx86::RAX as u8), temp as i64);
            let higher_bits = (temp as u128 >> 64) & 0xFFFFFFFFFFFFFFFF;
            _state.cpu.set_register(&(Registersx86::RDX as u8), higher_bits as i64);
        },
    }
}

fn decx86(size: usize, value1: i64, _state: &mut Statex86) -> i64
{
    let mut auxiliary = FlagDefined::Unset;
    if (value1 & 0xF) < (1 & 0xF) {
        auxiliary = FlagDefined::Set;
    }

    let result: i64 = match size{
        1=>{
            let (temp, _carry) = (value1 as u8).overflowing_sub(1);
            let _is_overflow = match (value1 as i8).checked_sub(1){
                Some(_v)=>FlagDefined::Unset,
                None=>FlagDefined::Set,
            };
            let v = temp as i8;
            let _is_carry = match _carry{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };

            set_all_flags(v, _is_overflow, auxiliary, FlagDefined::Undefined, _state);
            temp as i64
        },
        2=>{
            let (temp, _carry) = (value1 as u16).overflowing_sub(1);
            let _is_overflow = match (value1 as i16).checked_sub(1){
                Some(_v)=>FlagDefined::Unset,
                None=>FlagDefined::Set,
            };
            let v = temp as i16;
            let _is_carry = match _carry{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };

            set_all_flags(v, _is_overflow, auxiliary, FlagDefined::Undefined, _state);
            temp as i64
        },
        4=>{
            let (temp, _carry) = (value1 as u32).overflowing_sub(1);
            let _is_overflow = match (value1 as i32).checked_sub(1){
                Some(_v)=>FlagDefined::Unset,
                None=>FlagDefined::Set,
            };
            let v = temp as i32;
            let _is_carry = match _carry{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };
            set_all_flags(v, _is_overflow, auxiliary, FlagDefined::Undefined, _state);
            temp as i64
        },
        _=>{
            let (temp, _carry) = (value1 as u64).overflowing_sub(1);
            let _is_overflow = match (value1 as i64).checked_sub(1){
                Some(_v)=>FlagDefined::Unset,
                None=>FlagDefined::Set,
            };
            let _is_carry = match _carry{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };
            set_all_flags(temp as i64, _is_overflow, auxiliary, FlagDefined::Undefined, _state);
            temp as i64
        },
    };
    return result;
}

fn incx86(size: usize, value1: i64, _state: &mut Statex86) -> i64
{
    let mut auxiliary = FlagDefined::Unset;
    if (value1 & 0xF) < (1 & 0xF) {
        auxiliary = FlagDefined::Set;
    }

    let result: i64 = match size{
        1=>{
            let (temp, _carry) = (value1 as u8).overflowing_add(1);
            let _is_overflow = match (value1 as i8).checked_add(1){
                Some(_v)=>FlagDefined::Unset,
                None=>FlagDefined::Set,
            };
            let v = temp as i8;
            let _is_carry = match _carry{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };

            set_all_flags(v, _is_overflow, auxiliary, FlagDefined::Undefined, _state);
            temp as i64
        },
        2=>{
            let (temp, _carry) = (value1 as u16).overflowing_add(1);
            let _is_overflow = match (value1 as i16).checked_add(1){
                Some(_v)=>FlagDefined::Unset,
                None=>FlagDefined::Set,
            };
            let v = temp as i16;
            let _is_carry = match _carry{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };

            set_all_flags(v, _is_overflow, auxiliary, FlagDefined::Undefined, _state);
            temp as i64
        },
        4=>{
            let (temp, _carry) = (value1 as u32).overflowing_add(1);
            let _is_overflow = match (value1 as i32).checked_add(1){
                Some(_v)=>FlagDefined::Unset,
                None=>FlagDefined::Set,
            };
            let v = temp as i32;
            let _is_carry = match _carry{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };
            set_all_flags(v, _is_overflow, auxiliary, FlagDefined::Undefined, _state);
            temp as i64
        },
        _=>{
            let (temp, _carry) = (value1 as u64).overflowing_add(1);
            let _is_overflow = match (value1 as i64).checked_add(1){
                Some(_v)=>FlagDefined::Unset,
                None=>FlagDefined::Set,
            };
            let _is_carry = match _carry{
                true=>FlagDefined::Set,
                false=>FlagDefined::Unset,
            };
            set_all_flags(temp as i64, _is_overflow, auxiliary, FlagDefined::Undefined, _state);
            temp as i64
        },
    };
    return result;
}

fn stack_push(_value: i64, _mem_manager: &mut MemoryManager, _state: &mut Statex86 )
{
    let stack_pointer = match _state.cpu.address_size
    {
        2=>_state.cpu.get_register(&(Registersx86::SP as u8), 0),
        4=>_state.cpu.get_register(&(Registersx86::ESP as u8), 0),
        8=>_state.cpu.get_register(&(Registersx86::RSP as u8), 0),
        _=>0,
    };

    let stack_address = stack_pointer -_state.cpu.address_size as i64;
    let (is_stack, _base_addr, bounds_size) = _mem_manager.is_stack(stack_address as usize);
    if is_stack
    {
        let address_size = _state.cpu.address_size as usize;
        _state.stack_write(
            stack_address as u64, 
            _value, 
            address_size, 
            bounds_size);

        let new_stack_pointer = stack_pointer-address_size as i64;
        match address_size
        {
            2=>{
                _state.cpu.set_register(&(Registersx86::SP as u8), new_stack_pointer);
            },
            4=>{
                _state.cpu.set_register(&(Registersx86::ESP as u8), new_stack_pointer);
            },
            8=>{
                _state.cpu.set_register(&(Registersx86::RSP as u8), new_stack_pointer);
            },
            _=>{},
        }
    }   
}

fn stack_pop(_mem_manager: &mut MemoryManager, _state: &mut Statex86 ) -> i64
{
    let stack_pointer = match _state.cpu.address_size
    {
        2=>_state.cpu.get_register(&(Registersx86::SP as u8), 0),
        4=>_state.cpu.get_register(&(Registersx86::ESP as u8), 0),
        8=>_state.cpu.get_register(&(Registersx86::RSP as u8), 0),
        _=>0,
    };
    let (is_stack, _base_addr, _bounds_size) = _mem_manager.is_stack(stack_pointer as usize);
    if is_stack
    {
        let address_size = _state.cpu.address_size as usize;
        let new_value = _state.stack_read(
                                    stack_pointer, 
                                    address_size);

        let new_stack_pointer = stack_pointer+address_size as i64;
        match address_size
        {
            2=>{
                _state.cpu.set_register(&(Registersx86::SP as u8), new_stack_pointer);
            },
            4=>{
                _state.cpu.set_register(&(Registersx86::ESP as u8), new_stack_pointer);
            },
            8=>{
                _state.cpu.set_register(&(Registersx86::RSP as u8), new_stack_pointer);
            },
            _=>{},
        }
        return new_value;
    }
    return 0;
}

// INSTRUCTION MAPPING

pub fn check_data_transfer_instructions(
    _offset: u64, 
    _instr: &mut InstructionInfo, 
    _analysis: &mut Analysisx86,
    _mem_manager: &mut MemoryManager,
    _state: &mut Statex86) -> Option<Statex86>
{
    //debug!("check_data_transfer_instructions()");
    let index = DISASMX86_OPLOOKUP_MAP[_instr.instr.opcode as usize] as usize;
    match DISASMX86_OP_MAP[index] {
        // byte swap 
        // Changes the byte order of a 32 bit register from big endian to 
        // little endian or vice versa
        "bswap"=>{
            // get first operand
            let mut value: i64 = match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>_state.cpu.get_register(
                    &_instr.instr.detail.operands()[0].reg, _instr.instr.size),
                _=>0,
            };
            match _instr.instr.detail.operands()[0].size {
                2=>{
                    let u16_value = value as i16;
                    value = u16_value.swap_bytes() as i64;
                }
                4=>{
                    let u32_value = value as i32;
                    value = u32_value.swap_bytes() as i64;
                }
                8=>{
                    value = value.swap_bytes();
                }
                _=>{},
            }
            // set first operand
            match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>{
                    _state.cpu.set_register(
                        &_instr.instr.detail.operands()[0].reg, value);
                },
                _=>{},
            }
        },
        // move
        "mov"=>{
            // get second operand
            let value_size: usize = _instr.instr.detail.operands()[1].size as usize;
            let value: i64 = match _instr.instr.detail.operands()[1].op_type{
                InstrOpTypex86::Reg=>_state.cpu.get_register(
                    &_instr.instr.detail.operands()[1].reg,
                    _instr.instr.size),
                InstrOpTypex86::Imm=>{
                    let _value = _instr.instr.detail.operands()[1].imm;
                    let detail = _mem_manager.check_for_string(
                        _analysis,
                        _state,
                        _value as usize,
                        value_size);
                    if !detail.is_empty(){
                        _instr.detail.push( DetailInfo{
                            op_index: 0,
                            contents: detail,
                        });
                    }  
                    _value
                },
                InstrOpTypex86::Mem=>{
                    let (_address, _value) = get_memory_operand(
                        &_instr.instr.detail.operands()[1].mem,
                        _instr.instr.size,
                        value_size,
                        _analysis,
                        _mem_manager,
                        _state);
                    let detail = _mem_manager.check_for_string(
                        _analysis,
                        _state,
                        _address as usize,
                        value_size);
                    if !detail.is_empty(){
                        _instr.detail.push( DetailInfo{
                            op_index: 0,
                            contents: detail,
                        });
                    }  
                    _value
                },
                _=>0,
            };

            //debug!("0x{:x} {} {}=0x{:x} size {}", _offset, _instr.instr.mnemonic, _instr.instr.op_str, value, value_size);

            // set first operand
            match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>{
                    _state.cpu.set_register(
                        &_instr.instr.detail.operands()[0].reg, 
                        value);
                },
                InstrOpTypex86::Imm=>{},
                InstrOpTypex86::Mem=>{
                    let dest = set_memory_operand(
                        &_instr.instr.detail.operands()[0].mem,
                        value,
                        _instr.instr.size,
                        value_size,
                        _analysis,
                        _mem_manager,
                        _state);
                    let detail = _mem_manager.check_for_string(
                        _analysis,
                        _state,
                        dest as usize,
                        value_size);
                    if !detail.is_empty(){
                        _instr.detail.push( DetailInfo{
                            op_index: 0,
                            contents: detail,
                        });
                    }
                },
                _=>{},
            }
            // if address is executable section add to be analyzed as code
            if !_state.emulation_enabled && _mem_manager.is_executable(value as usize, _analysis)
            {
                let post_analysis: Option<Statex86> = Some(Statex86 
                    {
                        offset: value as usize,
                        cpu: _state.cpu.clone(), 
                        stack: _state.stack.clone(),
                        current_function_addr: 0,
                        emulation_enabled: _state.emulation_enabled,
                        loop_state: _state.loop_state.clone(),
                        analysis_type: AnalysisType::Data,
                    });
                return post_analysis;
            }
            return None;
        },
        // move absolute value immediate value to register
        "movabs"=>{
            // get second operand
            let value_size: usize = _instr.instr.detail.operands()[1].size as usize;
            let value: i64 = match _instr.instr.detail.operands()[1].op_type{
                InstrOpTypex86::Reg=>_state.cpu.get_register(
                    &_instr.instr.detail.operands()[1].reg, _instr.instr.size),
                InstrOpTypex86::Imm=>_instr.instr.detail.operands()[1].imm,
                InstrOpTypex86::Mem=>0, 
                _=>0,
            };
            //value = value.abs(); // causes an overflow error for 0x8000000000000000

            // flip the sign and store the same bytes
            if _state.cpu.get_flag(&EFlags::Sign) == 1
            {
                _state.cpu.set_flag(&EFlags::Sign, 0); 
            }
            // set first operand
            match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>{
                    _state.cpu.set_register(
                        &_instr.instr.detail.operands()[0].reg, 
                        value);
                },
                InstrOpTypex86::Imm=>{},
                InstrOpTypex86::Mem=>{
                    set_memory_operand(
                        &_instr.instr.detail.operands()[0].mem,
                        value,
                        _instr.instr.size,
                        value_size,
                        _analysis,
                        _mem_manager,
                        _state);
                }, 
                _=>{},
            }
        },
        // move and sign extend 
        "movsx" |
        "movsxd"=>{},
        // Move Data After Swapping Bytes
        "movbe"=>{
            let mut value: i64 = match _instr.instr.detail.operands()[1].op_type{
                InstrOpTypex86::Reg=>_state.cpu.get_register(
                    &_instr.instr.detail.operands()[1].reg, _instr.instr.size),
                InstrOpTypex86::Imm=>_instr.instr.detail.operands()[1].imm,
                InstrOpTypex86::Mem=>0,
                _=>0,
            };
            match _instr.instr.detail.operands()[1].size {
                2=>{
                    let u16_value = value as i16;
                    value = u16_value.swap_bytes() as i64;
                }
                4=>{
                    let u32_value = value as i32;
                    value = u32_value.swap_bytes() as i64;
                }
                8=>{
                    value = value.swap_bytes();
                }
                _=>{},
            }
            match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>{
                    _state.cpu.set_register(
                        &_instr.instr.detail.operands()[0].reg, 
                        value);
                },
                InstrOpTypex86::Imm=>{},
                InstrOpTypex86::Mem=>{

                },
                _=>{},
            }
        },
        // Move with Zero-Extend
        "movzx"=>{},
        // convert byte to word 
        "cbw"=>{},
        // convert quadword to octword 
        "cdq"=>{},
        // convert word to doubleword 
        "cdqe"=>{},
        // conditional move
        "cmova" |
        "cmovae" |
        "cmovb" |
        "cmovbe" |
        "cmove" |
        "cmovg" |
        "cmovge" |
        "cmovl" |
        "cmovle" |
        "cmovne" |
        "cmovno" |
        "cmovnp" |
        "cmovns" |
        "cmovo" |
        "cmovp" |
        "cmovs"=>{},
        // cmp and exchange
        "cmpxchg16b" |
        "cmpxchg" |
        "cmpxchg8b"=>{
            //accumulator = AL, AX, EAX, or RAX
            // TEMP ← DEST
            // IF accumulator = TEMP
            //     THEN
            //         ZF ← 1;
            //         DEST ← SRC;
            //     ELSE
            //         ZF ← 0;
            //         accumulator ← TEMP;
            //         DEST ← TEMP;
            // FI;
        },
        // pop
        "pop" |
        "popaw" |
        "popal"=>{
            // first operand
            let value_size: usize = _instr.instr.detail.operands()[0].size as usize;
            match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>{
                    let last_address = (_state.cpu.stack_address as usize) - (_state.stack.len() as usize);
                    let detail = _mem_manager.check_for_string(
                        _analysis,
                        _state,
                        last_address,
                        value_size);
                    if !detail.is_empty(){
                        _instr.detail.push( DetailInfo{
                            op_index: 0,
                            contents: detail,
                        });
                    }
                    let value = stack_pop(_mem_manager, _state);
                    _state.cpu.set_register(
                        &_instr.instr.detail.operands()[0].reg, 
                        value);
                    let detail = _mem_manager.check_for_string(
                        _analysis,
                        _state,
                        value as usize,
                        value_size);
                    if !detail.is_empty(){
                        _instr.detail.push( DetailInfo{
                            op_index: 0,
                            contents: detail,
                        });
                    }
                },
                InstrOpTypex86::Imm=>{},
                InstrOpTypex86::Mem=>{
                    let value = stack_pop(_mem_manager, _state);
                    set_memory_operand(
                        &_instr.instr.detail.operands()[0].mem,
                        value,
                        _instr.instr.size,
                        value_size,
                        _analysis,
                        _mem_manager,
                        _state);
                },
                _=>{},
            }
        },
        "popcnt"=>{},
        // push
        "push" |
        "pushaw" |
        "pushal"=>{
            let value_size: usize = _instr.instr.detail.operands()[0].size as usize;
            // first operand

            match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>{
                    let reg = _state.cpu.get_register(
                        &_instr.instr.detail.operands()[0].reg,
                        _instr.instr.size);
                    stack_push(reg, _mem_manager, _state);
                },
                InstrOpTypex86::Imm=>{
                    let imm = _instr.instr.detail.operands()[0].imm;
                    stack_push(imm, _mem_manager, _state);
                    let detail = _mem_manager.check_for_string(
                        _analysis,
                        _state,
                        imm as usize,
                        value_size);
                    let detail2 = transmute_integer(imm as usize, value_size);
                    if !detail.is_empty(){
                        _instr.detail.push( DetailInfo{
                            op_index: 0,
                            contents: detail,
                        });
                    } else if !detail2.is_empty(){
                        _instr.detail.push( DetailInfo{
                            op_index: 0,
                            contents: detail2,
                        });
                    }
                },
                InstrOpTypex86::Mem=>{
                    let (_address, _value) = get_memory_operand(
                        &_instr.instr.detail.operands()[0].mem,
                        _instr.instr.size,
                        value_size,
                        _analysis,
                        _mem_manager,
                        _state);
                    stack_push(_value, _mem_manager, _state);
                },
                _=>{},

            }
        },
        // exchange and add
        "xadd"=>{
            //TEMP ← SRC + DEST;
            //SRC ← DEST;
            //DEST ← TEMP;
            // get first operand
            let value1: i64 = match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>_state.cpu.get_register(
                    &_instr.instr.detail.operands()[0].reg, _instr.instr.size),
                InstrOpTypex86::Imm=>_instr.instr.detail.operands()[0].imm,
                InstrOpTypex86::Mem=>0, 
                _=>0,
            };
            let value2: i64 = match _instr.instr.detail.operands()[1].op_type{
                InstrOpTypex86::Reg=>_state.cpu.get_register(
                    &_instr.instr.detail.operands()[1].reg, _instr.instr.size),
                InstrOpTypex86::Imm=>_instr.instr.detail.operands()[1].imm,
                InstrOpTypex86::Mem=>0, 
                _=>0,
            };

            let temp = value1 + value2;
            // set first operand
            match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>{
                    _state.cpu.set_register(
                        &_instr.instr.detail.operands()[0].reg, 
                        temp);
                },
                InstrOpTypex86::Imm=>{},
                InstrOpTypex86::Mem=>{}, 
                _=>{},
            }
            // set second operand
            match _instr.instr.detail.operands()[1].op_type{
                InstrOpTypex86::Reg=>{
                    _state.cpu.set_register(
                        &_instr.instr.detail.operands()[1].reg, 
                        value1);
                },
                InstrOpTypex86::Imm=>{},
                InstrOpTypex86::Mem=>{}, 
                _=>{},
            }
        },
        // exchange
        "xchg"=>{
            let value1: i64 = match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>_state.cpu.get_register(
                    &_instr.instr.detail.operands()[0].reg, _instr.instr.size),
                InstrOpTypex86::Imm=>_instr.instr.detail.operands()[0].imm,
                InstrOpTypex86::Mem=>0, 
                _=>0,
            };
            let value2: i64 = match _instr.instr.detail.operands()[1].op_type{
                InstrOpTypex86::Reg=>_state.cpu.get_register(
                    &_instr.instr.detail.operands()[1].reg, _instr.instr.size),
                InstrOpTypex86::Imm=>_instr.instr.detail.operands()[1].imm,
                InstrOpTypex86::Mem=>0, 
                _=>0,
            };
            match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>{
                    _state.cpu.set_register(
                        &_instr.instr.detail.operands()[0].reg, 
                        value2);
                },
                InstrOpTypex86::Imm=>{},
                InstrOpTypex86::Mem=>{}, 
                _=>{},
            }
            match _instr.instr.detail.operands()[1].op_type{
                InstrOpTypex86::Reg=>{
                    _state.cpu.set_register(
                        &_instr.instr.detail.operands()[1].reg, 
                        value1);
                },
                InstrOpTypex86::Imm=>{},
                InstrOpTypex86::Mem=>{},
                _=>{},
            }
        },      
        _=>{},
    }
    return None;
}

fn check_binary_arithmetic_instructions(
    _offset: u64, 
    _instr: &mut InstructionInfo, 
    _analysis: &mut Analysisx86,
    _mem_manager: &mut MemoryManager,
    _state: &mut Statex86)
{
    //debug!("check_binary_arithmetic_instructions()");
    let index = DISASMX86_OPLOOKUP_MAP[_instr.instr.opcode as usize] as usize;
    match DISASMX86_OP_MAP[index] {
        // ADC add with carry
        "adc" |
        "adcx"=>{
            // get second operand
            let value2 = get_operand!(index: 1; _instr; _analysis; _state; _mem_manager);
            // get first operand
            let value1 = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);
            let value1_size: usize = _instr.instr.detail.operands()[0].size as usize;
            //get carry flag
            let cflag = _state.cpu.get_flag(&EFlags::Carry) as i64;

            let result = addx86(value1_size, value1, value2 + cflag, _state);

            //debug!("0x{:x} {} 0x{:x}=0x{:x}+0x{:x}+0x{:x}", 
            //            _offset, _instr.instr.mnemonic, result, value1, value2, cflag);

            set_operand!(value: result; index: 0; _instr; _analysis; _state; _mem_manager);

        },
        // ADD integer add
        "add"=>{
            // get second operand
            let value2 = get_operand!(index: 1; _instr; _analysis; _state; _mem_manager);
            // get first operand
            let value1 = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);
            let value1_size: usize = _instr.instr.detail.operands()[0].size as usize;
            let result = addx86(value1_size, value1, value2, _state);

            //debug!("0x{:x} {} 0x{:x}=0x{:x}+0x{:x}", 
            //            _offset, _instr.instr.mnemonic, result, value1, value2);

            set_operand!(value: result; index: 0; _instr; _analysis; _state; _mem_manager);
        },
        // CMP compare
        "cmp" =>{
            // get second operand
            let value2 = get_operand!(index: 1; _instr; _analysis; _state; _mem_manager);
            // get first operand
            let value1 = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);
            let value1_size: usize = _instr.instr.detail.operands()[0].size as usize;
            // sub operation
           
            let _result = subx86(value1_size, value1, value2, _state);

            //debug!("0x{:x} {} 0x{:x}=0x{:x} - 0x{:x}", 
            //            _offset, _instr.instr.mnemonic, _result, value1, value2);
        },
        "cmpsb"=>{
            // get second operand
            let value2 = get_operand!(index: 1; _instr; _analysis; _state; _mem_manager);
            // get first operand
            let value1 = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);
            let value1_size: usize = _instr.instr.detail.operands()[0].size as usize;
            // sub operation

            // ESI & EDI increment
            if _state.cpu.get_flag(&EFlags::Direction) == 0 {
                _state.cpu.regs.esi.value+=1;
                _state.cpu.regs.edi.value+=1;
            } else {
                _state.cpu.regs.esi.value-=1;
                _state.cpu.regs.edi.value-=1;
            }

            // sub operation
            let _result = subx86(value1_size, value1, value2, _state);

            //debug!("0x{:x} {} 0x{:x}=0x{:x} - 0x{:x}", 
            //            _offset, _instr.instr.mnemonic, _result, value1, value2);
        },
        "cmpsd" |
        "cmpsq"=>{},
        // DEC decrement
        "dec"=>{
            // get first operand
            let value1_size: usize = _instr.instr.detail.operands()[0].size as usize;
            let value1: i64 = match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>_state.cpu.get_register(
                    &_instr.instr.detail.operands()[0].reg,
                    _instr.instr.size),
                _=>0,
            };

            let result = decx86(value1_size, value1, _state);

            //debug!("0x{:x} {} 0x{:x}=0x{:x} - 0x{:x}", 
            //            _offset, _instr.instr.mnemonic, result, value1, 1);

            set_operand!(value: result as i64; index: 0; _instr; _analysis; _state; _mem_manager);
        },
        // DIV divide (unsigned)
        "div"=>{},
        // IDIV divide (signed)     
        "idiv"=>{},
        // IMUL multiply (signed)
        "imul"=>{
            //let value_size: usize = _instr.instr.detail.operands()[0].size as usize;
            //let src = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);
            //binary_mul(true, value_size, src, _state);
        },
        // MUL multiply
        "mul"=>{
            let value_size: usize = _instr.instr.detail.operands()[0].size as usize;
            let src = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);
            
            mulx86(false, value_size, src, _state);
        },
        // INC increment
        "inc"=>{
            // get first operand
            let value1_size: usize = _instr.instr.detail.operands()[0].size as usize;
            let value1: i64 = match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>_state.cpu.get_register(
                    &_instr.instr.detail.operands()[0].reg,
                    _instr.instr.size),
                _=>0,
            };

            let result = incx86(value1_size, value1, _state);

            //debug!("0x{:x} {} 0x{:x}=0x{:x}+0x{:x}", 
            //            _offset, _instr.instr.mnemonic, result, value1, 1);

            set_operand!(value: result; index: 0; _instr; _analysis; _state; _mem_manager);
        },
        // NEG negate
        "neg"=>{
            // get first operand
            let value1: i64 = match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>_state.cpu.get_register(
                    &_instr.instr.detail.operands()[0].reg,
                    _instr.instr.size),
                _=>0,
            };


            let _is_carry = match value1 {
                0=>FlagDefined::Unset,
                _=>FlagDefined::Set,

            };
            // TODO: fix this
            let mut auxiliary = FlagDefined::Unset;
            
            // set first operand
            match _state.cpu.address_size{
                2=>{
                    let (temp, ov) = (value1 as i16).overflowing_neg();
                    set_operand!(value: temp as i64; index: 0; _instr; _analysis; _state; _mem_manager);
                    //Set Flags
                    let _is_overflow = match ov{
                        true=>FlagDefined::Set,
                        false=>FlagDefined::Unset,
                    };
                    set_all_flags(temp, _is_overflow, auxiliary, _is_carry, _state);
                    //debug!("0x{:x} {} 0x{:x}=0x{:x}", 
                    //    _offset, _instr.instr.mnemonic, temp, value1);
                },
                4=>{
                    let (temp, ov) = (value1 as i32).overflowing_neg();
                    set_operand!(value: temp as i64; index: 0; _instr; _analysis; _state; _mem_manager);
                    let _is_overflow = match ov{
                        true=>FlagDefined::Set,
                        false=>FlagDefined::Unset,
                    };
                    //Set Flags
                    set_all_flags(temp, _is_overflow, auxiliary, _is_carry, _state);
                    //debug!("0x{:x} {} 0x{:x}=0x{:x}", 
                    //    _offset, _instr.instr.mnemonic, temp, value1);
                },
                _=>{
                    let (temp, ov) = (value1 as i64).overflowing_neg();
                    set_operand!(value: temp as i64; index: 0; _instr; _analysis; _state; _mem_manager);
                    let _is_overflow = match ov{
                        true=>FlagDefined::Set,
                        false=>FlagDefined::Unset,
                    };
                    //Set Flags
                    set_all_flags(temp, _is_overflow, auxiliary, _is_carry, _state);
                    //debug!("0x{:x} {} 0x{:x}=0x{:x}", 
                    //    _offset, _instr.instr.mnemonic, temp, value1);
                },
            }
        },
        // SBB subtract with borrow
        "sbb"=>{
            // get second operand
            let value2 = get_operand!(index: 1; _instr; _analysis; _state; _mem_manager);
            let value1 = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);
            let value1_size: usize = _instr.instr.detail.operands()[0].size as usize;
            //get carry flag
            let cflag = _state.cpu.get_flag(&EFlags::Carry) as i64;
            // sub operation
            let result = subx86(value1_size, value1 + cflag, value2, _state);

            //debug!("0x{:x} {} 0x{:x}=0x{:x} - 0x{:x}", 
            //            _offset, _instr.instr.mnemonic, result, value1 + cflag, value2);
            set_operand!(value: result as i64; index: 0; _instr; _analysis; _state; _mem_manager);
        },
        // SUB subtract
        "sub"=>{
            // get second operand
            let value2 = get_operand!(index: 1; _instr; _analysis; _state; _mem_manager);
            let value1 = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);
            let value1_size: usize = _instr.instr.detail.operands()[0].size as usize;

            // sub operation
            let result = subx86(value1_size, value1, value2, _state);

            //debug!("0x{:x} {} 0x{:x}=0x{:x} - 0x{:x}", 
            //            _offset, _instr.instr.mnemonic, result, value1, value2);
            set_operand!(value: result as i64; index: 0; _instr; _analysis; _state; _mem_manager);
        },
        _=>{},
    }
}

fn check_logical_instructions(
    _offset: u64, 
    _instr: &mut InstructionInfo, 
    _analysis: &mut Analysisx86,
    _mem_manager: &mut MemoryManager,
    _state: &mut Statex86)
{
    //debug!("check_logical_instructions()");
    let index = DISASMX86_OPLOOKUP_MAP[_instr.instr.opcode as usize] as usize;
    match DISASMX86_OP_MAP[index] {
        // AND
        "and"=>{
            let value2 = get_operand!(index: 1; _instr; _analysis; _state; _mem_manager);
            let value1 = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);

            let temp = value1 & value2;
            //debug!("0x{:x} {} 0x{:x}=0x{:x} - 0x{:x}", 
            //            _offset, _instr.instr.mnemonic, temp, value1, value2);
            // set first operand
            set_operand!(value: temp; index: 0; _instr; _analysis; _state; _mem_manager);

            set_all_flags(temp, FlagDefined::Unset, FlagDefined::Undefined, FlagDefined::Unset, _state);
        },
        // OR
        "or"=>{
            let value2 = get_operand!(index: 1; _instr; _analysis; _state; _mem_manager);
            let value1 = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);

            let temp = value1 | value2;
            //debug!("0x{:x} {} 0x{:x}=0x{:x} - 0x{:x}", 
            //            _offset, _instr.instr.mnemonic, temp, value1, value2);
            // set first operand
            set_operand!(value: temp; index: 0; _instr; _analysis; _state; _mem_manager);
            set_all_flags(temp, FlagDefined::Unset, FlagDefined::Undefined, FlagDefined::Unset, _state);
        },
        // NOT
        "not"=>{
            // get first operand
            let value1: i64 = match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>_state.cpu.get_register(
                    &_instr.instr.detail.operands()[0].reg,
                    _instr.instr.size),
                InstrOpTypex86::Imm=>0,
                InstrOpTypex86::Mem=>0, 
                _=>0,
            };
            let temp = !value1;
            // set first operand
            match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>{
                    _state.cpu.set_register(
                        &_instr.instr.detail.operands()[0].reg, 
                        temp);
                },
                InstrOpTypex86::Imm=>{},
                InstrOpTypex86::Mem=>{},
                _=>{},
            }
            set_all_flags(temp, FlagDefined::Unset, FlagDefined::Undefined, FlagDefined::Undefined, _state);
        },
        // XOR
        "xor"=>{
            // get second operand
            let value2 = get_operand!(index: 1; _instr; _analysis; _state; _mem_manager);
            let value1 = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);

            let temp = value1^value2;
            //debug!("0x{:x} {} 0x{:x}=0x{:x} - 0x{:x}", 
            //        _offset, _instr.instr.mnemonic, temp, value1, value2);
            // set first operand
            set_operand!(value: temp; index: 0; _instr; _analysis; _state; _mem_manager);
            set_all_flags(temp, FlagDefined::Unset, FlagDefined::Undefined, FlagDefined::Unset, _state);
        },
        _=>{},
    }
}

fn check_shift_rotate_instructions(
    _offset: u64, 
    _instr: &mut InstructionInfo, 
    _analysis: &mut Analysisx86,
    _mem_manager: &mut MemoryManager,
    _state: &mut Statex86)
{
    //debug!("check_shift_rotate_instructions()");
    let index = DISASMX86_OPLOOKUP_MAP[_instr.instr.opcode as usize] as usize;
    match DISASMX86_OP_MAP[index] {
        //RCL rotate through carry left
        "rcl" =>{},
        //RCR rotate through carry right
        "rcr" =>{},
        //ROL rotate left
        "rol" =>{
            // get first operand
            let mut value2 = get_operand!(index: 1; _instr; _analysis; _state; _mem_manager);
            if value2 == 0{
                value2 = 1; //default
            }
            let value1 = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);
            let value1_size: usize = _instr.instr.detail.operands()[0].size as usize;

            let temp = match value1_size{
                1=>{
                    let v = (value1 as u8).rotate_left(value2 as u32);
                    (v as i8) as i64
                },
                2=>{
                    let v = (value1 as u16).rotate_left(value2 as u32);
                    (v as i16) as i64
                },
                4=>{
                    let v = (value1 as u32).rotate_left(value2 as u32);
                    (v as i32) as i64
                },
                _=>{
                    let v = (value1 as u64).rotate_left(value2 as u32);
                    v as i64
                },
            };

            //debug!("0x{:x} {} 0x{:x}=0x{:x} - 0x{:x}", 
            //            _offset, _instr.instr.mnemonic, temp, value1, value2);

            set_operand!(value: temp as i64; index: 0; _instr; _analysis; _state; _mem_manager);
        },
        "ror" | "rorx" =>{
            // get first operand
            let mut value2 = get_operand!(index: 1; _instr; _analysis; _state; _mem_manager);
            if value2 == 0{
                value2 = 1; //default 
            }
            let value1 = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);
            let value1_size: usize = _instr.instr.detail.operands()[0].size as usize;

            let temp = match value1_size{
                1=>{
                    let v = (value1 as u8).rotate_right(value2 as u32);
                    (v as i8) as i64
                },
                2=>{
                    let v = (value1 as u16).rotate_right(value2 as u32);
                    (v as i16) as i64
                },
                4=>{
                    let v = (value1 as u32).rotate_right(value2 as u32);
                    (v as i32) as i64
                },
                _=>{
                    let v = (value1 as u64).rotate_right(value2 as u32);
                    v as i64
                },
            };

            //debug!("0x{:x} {} 0x{:x}=0x{:x} - 0x{:x}", 
            //            _offset, _instr.instr.mnemonic, temp, value1, value2);

            set_operand!(value: temp as i64; index: 0; _instr; _analysis; _state; _mem_manager);
        },
        //SAL shift arithmetic left (signed)
        "sal" | "salc" =>{
            // get first operand
            let mut value2 = get_operand!(index: 1; _instr; _analysis; _state; _mem_manager);
            if value2 == 0{
                value2 = 1; //default 
            }
            let value1 = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);
            let value1_size: usize = _instr.instr.detail.operands()[0].size as usize;

            let (temp, _is_carry, _is_overflow) = match value1_size{
                1=>{
                    let (v, _carry) = (value1 as i8).overflowing_shl(value2 as u32);
                    ((v as i8) as i64, FlagDefined::Undefined, FlagDefined::Unset)
                },
                2=>{
                    let (v, mut _carry) = (value1 as i16).overflowing_shl(value2 as u32);
                    if 2 < _state.cpu.address_size {
                        _carry = false;
                    } 
                    let mut overflow = FlagDefined::Undefined;

                    let mut _is_carry = FlagDefined::Unset;

                    if _carry{
                        _is_carry = FlagDefined::Set;
                        if value2 == 1
                        {
                            overflow = FlagDefined::Set;
                        }

                    } else {
                        _is_carry = FlagDefined::Unset;
                        if value2 == 1
                        {
                            overflow = FlagDefined::Set;
                        }
                    }
                    
                    ((v as i16) as i64, _is_carry, overflow) 
                },
                4=>{
                    let (v, mut _carry) = (value1 as i32).overflowing_shl(value2 as u32);
                    if 4 < _state.cpu.address_size {
                        _carry = false;
                    }
                    let mut overflow = FlagDefined::Undefined;
                    let mut _is_carry = FlagDefined::Unset;

                    if _carry{
                        _is_carry = FlagDefined::Set;
                        if value2 == 1
                        {
                            overflow = FlagDefined::Set;
                        }

                    } else {
                        _is_carry = FlagDefined::Unset;
                        if value2 == 1
                        {
                            overflow = FlagDefined::Set;
                        }
                    }
                    ((v as i32) as i64, _is_carry, overflow)
                },
                _=>{
                    let (v, _carry) = (value1 as i64).overflowing_shl(value2 as u32);
                    let mut overflow = FlagDefined::Undefined;
                    let mut _is_carry = FlagDefined::Unset;

                    if _carry{
                        _is_carry = FlagDefined::Set;
                        if value2 == 1
                        {
                            overflow = FlagDefined::Set;
                        }

                    } else {
                        _is_carry = FlagDefined::Unset;
                        if value2 == 1
                        {
                            overflow = FlagDefined::Set;
                        }
                    }
                    (v as i64, _is_carry, overflow)
                },
            };

            match _state.cpu.address_size{
                2=>{

                    set_all_flags(temp as i16, _is_overflow, FlagDefined::Undefined, _is_carry, _state);
                },
                4=>{
                    set_all_flags(temp as i32, _is_overflow, FlagDefined::Undefined, _is_carry, _state);
                },
                _=>{
                    set_all_flags(temp as i64, _is_overflow, FlagDefined::Undefined, _is_carry, _state);
                },
            }

            //debug!("0x{:x} {} 0x{:x}=0x{:x} - 0x{:x}", 
            //            _offset, _instr.instr.mnemonic, temp, value1, value2);

            set_operand!(value: temp as i64; index: 0; _instr; _analysis; _state; _mem_manager);
        },
        //SAR shift arithmetic right (signed)
        "sar" | "sarx" =>{
            // get first operand
            let mut value2 = get_operand!(index: 1; _instr; _analysis; _state; _mem_manager);
            if value2 == 0{
                value2 = 1; //default shift >> 1
            } else {
                value2 = value2 & 0x1F;
            }

            let value1_size: usize = _instr.instr.detail.operands()[0].size as usize;
            let value1 = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);
            let mut carry = FlagDefined::Unset;
            let mut mask = 0;
            if value2 > 0{
                mask = 2i64.pow((value2-1) as u32);
            };
            if (value1 & mask) > 0 {
                carry = FlagDefined::Set;
            }

            let (temp, _is_overflow) = match value1_size{
                1=>{
                    let (v, _overflow) = (value1 as i8).overflowing_shr(value2 as u32);
                    ((v as i8) as i64, FlagDefined::Unset)
                },
                2=>{
                    let (v, mut ov) = (value1 as i16).overflowing_shr(value2 as u32);
                    let mut overflow = FlagDefined::Unset;
                    if ov{
                        overflow = FlagDefined::Set;
                    }
                    if 2 < _state.cpu.address_size {
                        overflow = FlagDefined::Unset;
                    }
                    ((v as i16) as i64, overflow) 
                },
                4=>{
                    let (v, mut ov) = (value1 as i32).overflowing_shr(value2 as u32);
                    let mut overflow = FlagDefined::Unset;
                    if ov{
                        overflow = FlagDefined::Set;
                    }
                    if 4 < _state.cpu.address_size {
                        overflow = FlagDefined::Unset;
                    }
                    ((v as i32) as i64, overflow)
                },
                _=>{
                    let (v, ov) = (value1 as i64).overflowing_shr(value2 as u32);
                    let mut overflow = FlagDefined::Unset;
                    if ov{
                        overflow = FlagDefined::Set;
                    }
                    (v as i64, overflow)
                },
            };

            match _state.cpu.address_size{
                2=>{

                    set_all_flags(temp as i16, _is_overflow, FlagDefined::Undefined, carry, _state);
                },
                4=>{
                    set_all_flags(temp as i32, _is_overflow, FlagDefined::Undefined, carry, _state);
                },
                _=>{
                    set_all_flags(temp as i64, _is_overflow, FlagDefined::Undefined, carry, _state);
                },
            }

            //debug!("0x{:x} {} 0x{:x}=0x{:x} - 0x{:x}", 
            //            _offset, _instr.instr.mnemonic, temp, value1, value2);

            set_operand!(value: temp as i64; index: 0; _instr; _analysis; _state; _mem_manager);
        },
        //SHL shift logical left (unsigned)
        "shl" | "shlx"=>{
            // get first operand
            let mut value2 = get_operand!(index: 1; _instr; _analysis; _state; _mem_manager);
            if value2 == 0{
                value2 = 1; //default 
            }
            let value1 = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);
            let value1_size: usize = _instr.instr.detail.operands()[0].size as usize;

            let (temp, _is_carry, _is_overflow) = match value1_size{
                1=>{
                    let (v, _carry) = (value1 as u8).overflowing_shl(value2 as u32);
                    ((v as i8) as i64, FlagDefined::Undefined, FlagDefined::Unset)
                },
                2=>{
                    let (v, mut _carry) = (value1 as u16).overflowing_shl(value2 as u32);
                    if 2 < _state.cpu.address_size {
                        _carry = false;
                    } 
                    let mut overflow = FlagDefined::Undefined;

                    let mut _is_carry = FlagDefined::Unset;

                    if _carry{
                        _is_carry = FlagDefined::Set;
                        if value2 == 1
                        {
                            overflow = FlagDefined::Set;
                        }

                    } else {
                        _is_carry = FlagDefined::Unset;
                        if value2 == 1
                        {
                            overflow = FlagDefined::Set;
                        }
                    }
                    
                    ((v as i16) as i64, _is_carry, overflow) 
                },
                4=>{
                    let (v, mut _carry) = (value1 as u32).overflowing_shl(value2 as u32);
                    if 4 < _state.cpu.address_size {
                        _carry = false;
                    }
                    let mut overflow = FlagDefined::Undefined;
                    let mut _is_carry = FlagDefined::Unset;

                    if _carry{
                        _is_carry = FlagDefined::Set;
                        if value2 == 1
                        {
                            overflow = FlagDefined::Set;
                        }

                    } else {
                        _is_carry = FlagDefined::Unset;
                        if value2 == 1
                        {
                            overflow = FlagDefined::Set;
                        }
                    }
                    ((v as i32) as i64, _is_carry, overflow)
                },
                _=>{
                    let (v, _carry) = (value1 as u64).overflowing_shl(value2 as u32);
                    let mut overflow = FlagDefined::Undefined;
                    let mut _is_carry = FlagDefined::Unset;

                    if _carry{
                        _is_carry = FlagDefined::Set;
                        if value2 == 1
                        {
                            overflow = FlagDefined::Set;
                        }

                    } else {
                        _is_carry = FlagDefined::Unset;
                        if value2 == 1
                        {
                            overflow = FlagDefined::Set;
                        }
                    }
                    (v as i64, _is_carry, overflow)
                },
            };

            match _state.cpu.address_size{
                2=>{

                    set_all_flags(temp as i16, _is_overflow, FlagDefined::Undefined, _is_carry, _state);
                },
                4=>{
                    set_all_flags(temp as i32, _is_overflow, FlagDefined::Undefined, _is_carry, _state);
                },
                _=>{
                    set_all_flags(temp as i64, _is_overflow, FlagDefined::Undefined, _is_carry, _state);
                },
            }

            //debug!("0x{:x} {} 0x{:x}=0x{:x} - 0x{:x}", 
            //            _offset, _instr.instr.mnemonic, temp, value1, value2);

            set_operand!(value: temp as i64; index: 0; _instr; _analysis; _state; _mem_manager);
        },
        //SHLD shift left double
        "shld"=>{},
        //SHR shift logical right (unsigned)
        "shr" | "shrx"=>{
            // get first operand
            let mut value2 = get_operand!(index: 1; _instr; _analysis; _state; _mem_manager);
            if value2 == 0{
                value2 = 1; //default shift >> 1
            } else {
                value2 = value2 & 0x1F;
            }

            let value1_size: usize = _instr.instr.detail.operands()[0].size as usize;
            let value1 = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);

            //debug!("0x{:x} {} 0x{:x} >> 0x{:x}", 
            //            _offset, _instr.instr.mnemonic, value1, value2);
            let mut carry = FlagDefined::Unset;
            let mut mask = 0;
            if value2 > 0{
                mask = 2i64.pow((value2-1) as u32);
            };
            
            if (value1 & mask as i64) > 0 {
                carry = FlagDefined::Set;
            }

            let (temp, _is_overflow) = match value1_size{
                1=>{
                    let (v, _overflow) = (value1 as u8).overflowing_shr(value2 as u32);
                    ((v as i8) as i64, FlagDefined::Unset)
                },
                2=>{
                    let (v, mut ov) = (value1 as u16).overflowing_shr(value2 as u32);
                    let mut overflow = FlagDefined::Unset;
                    if ov{
                        overflow = FlagDefined::Set;
                    }
                    if 2 < _state.cpu.address_size {
                        overflow = FlagDefined::Unset;
                    }
                    ((v as i16) as i64, overflow) 
                },
                4=>{
                    let (v, mut ov) = (value1 as u32).overflowing_shr(value2 as u32);
                    let mut overflow = FlagDefined::Unset;
                    if ov{
                        overflow = FlagDefined::Set;
                    }
                    if 4 < _state.cpu.address_size {
                        overflow = FlagDefined::Unset;
                    }
                    ((v as i32) as i64, overflow)
                },
                _=>{
                    let (v, ov) = (value1 as u64).overflowing_shr(value2 as u32);
                    let mut overflow = FlagDefined::Unset;
                    if ov{
                        overflow = FlagDefined::Set;
                    }
                    (v as i64, overflow)
                },
            };

            match _state.cpu.address_size{
                2=>{

                    set_all_flags(temp as i16, _is_overflow, FlagDefined::Undefined, carry, _state);
                },
                4=>{
                    set_all_flags(temp as i32, _is_overflow, FlagDefined::Undefined, carry, _state);
                },
                _=>{
                    set_all_flags(temp as i64, _is_overflow, FlagDefined::Undefined, carry, _state);
                },
            }


            set_operand!(value: temp as i64; index: 0; _instr; _analysis; _state; _mem_manager);
        },
        //SHRD shift right double
        "shrd"=>{},
        _=>{},
    }
}

fn check_bitbyte_instructions(
    _offset: u64, 
    _instr: &mut InstructionInfo, 
    _analysis: &mut Analysisx86,
    _mem_manager: &mut MemoryManager,
    _state: &mut Statex86)
{
    //debug!("check_bitbyte_instructions()");
    let index = DISASMX86_OPLOOKUP_MAP[_instr.instr.opcode as usize] as usize;
    match DISASMX86_OP_MAP[index] {
        "test"=>{
            // get second operand
            let value2 = get_operand!(index: 1; _instr; _analysis; _state; _mem_manager);
            let value1 = get_operand!(index: 0; _instr; _analysis; _state; _mem_manager);
            // and operation
            let temp = value1 & value2;

            //Set Flags
            _state.cpu.set_flag(&EFlags::Carry, 0);
            _state.cpu.set_flag(&EFlags::Overflow, 0);
            if temp < 0
            {
                _state.cpu.set_flag(&EFlags::Sign, 1);
            } 
            else if temp == 0 {
                _state.cpu.set_flag(&EFlags::Sign, 0);
                _state.cpu.set_flag(&EFlags::Zero, 1);
            }
            if ((temp & 0xff).count_ones() % 2) == 0 //is even # of ones
            {
                _state.cpu.set_flag(&EFlags::Parity, 1);
            } else {
                _state.cpu.set_flag(&EFlags::Parity, 0);
            }
        },
        _=>{},
    }
}

fn check_control_transfer_instructions(
    _offset: u64, 
    _instr: &mut InstructionInfo, 
    _analysis: &mut Analysisx86,
    _mem_manager: &mut MemoryManager,
    _state: &mut Statex86)
{
    //debug!("check_misc_instructions()");
    let index = DISASMX86_OPLOOKUP_MAP[_instr.instr.opcode as usize] as usize;
    match DISASMX86_OP_MAP[index] {
        "leave"=>{
            match _state.cpu.address_size{
                2=>{
                    let base_pointer = _state.cpu.get_register(&(Registersx86::BP as u8), 0);
                    _state.cpu.set_register(
                        &(Registersx86::SP as u8), 
                        base_pointer);
                    let value = stack_pop(_mem_manager, _state);
                    _state.cpu.set_register(
                        &(Registersx86::BP as u8), 
                        value);

                },
                4=>{
                    let base_pointer = _state.cpu.get_register(&(Registersx86::EBP as u8), 0);
                    _state.cpu.set_register(
                        &(Registersx86::ESP as u8), 
                        base_pointer);
                    let value = stack_pop(_mem_manager, _state);
                    _state.cpu.set_register(
                        &(Registersx86::EBP as u8), 
                        value);
                },
                8=>{
                    let base_pointer = _state.cpu.get_register(&(Registersx86::RBP as u8), 0);
                    _state.cpu.set_register(
                        &(Registersx86::RSP as u8), 
                        base_pointer);
                    let value = stack_pop(_mem_manager, _state);
                    _state.cpu.set_register(
                        &(Registersx86::RBP as u8), 
                        value);
                },
                _=>{}
            }
        },
        _=>{},
    }
}

fn check_misc_instructions(
    _offset: u64, 
    _instr: &mut InstructionInfo, 
    _analysis: &mut Analysisx86,
    _mem_manager: &mut MemoryManager,
    _state: &mut Statex86)
{
    //debug!("check_misc_instructions()");
    let index = DISASMX86_OPLOOKUP_MAP[_instr.instr.opcode as usize] as usize;
    match DISASMX86_OP_MAP[index] {
        "cpuid"=>{
        },
        "lea"=>{
            // get second operand address
            let value_size: usize = _instr.instr.detail.operands()[1].size as usize;
            let value: i64 = match _instr.instr.detail.operands()[1].op_type{
                InstrOpTypex86::Mem=>{
                    let (_address, _value) = get_memory_operand(
                        &_instr.instr.detail.operands()[1].mem,
                        _instr.instr.size,
                        value_size,
                        _analysis,
                        _mem_manager,
                        _state);
                    let detail = _mem_manager.check_for_string(
                        _analysis,
                        _state,
                        _address as usize,
                        value_size);
                    if !detail.is_empty(){
                        _instr.detail.push( DetailInfo{
                            op_index: 0,
                            contents: detail,
                        });
                    }
                    _address
                },
                _=>0,
            };
            // set first operand
            match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Reg=>{
                    _state.cpu.set_register(
                        &_instr.instr.detail.operands()[0].reg, 
                        value);
                },
                _=>{},
            }
        },
        "xlat" | "xlatb"=>{
        },
        _=>{},
    }
}

pub fn check_call(
    _offset: u64, 
    _instr: &mut InstructionInfo, 
    _analysis: &mut Analysisx86,
    _mem_manager: &mut MemoryManager,
    _state: &mut Statex86) -> (Option<Statex86>, Option<Statex86>)
{
    //debug!("check_call()");
    let mut _left_destination: u64 = 0;
    let mut _right_destination: u64 = 0;
    let index = DISASMX86_OPLOOKUP_MAP[_instr.instr.opcode as usize] as usize;
    let is_call = match DISASMX86_OP_MAP[index] {
        "call" | "lcall"=>true,
        _=>false,
    };
    if is_call{
        //debug!("\tis call");
        _left_destination = (_offset as u64) + (_instr.instr.size as u64);
        let _next_instruction = (_offset as u64) + (_instr.instr.size as u64);
        // get first operand
        let value_size: usize = _instr.instr.detail.operands()[0].size as usize;
        //let mut call_address: Option<u64> = None;
        let mut _address: i64 = 0;
        match _instr.instr.detail.operands()[0].op_type
        {
            InstrOpTypex86::Reg=>{
                _right_destination = _state.cpu.get_register(
                    &_instr.instr.detail.operands()[0].reg,
                    _instr.instr.size).abs() as u64;
            },
            InstrOpTypex86::Imm=>{
                _right_destination = _instr.instr.detail.operands()[0].imm.abs() as u64;
            },
            InstrOpTypex86::Mem=>{
                let (ptr_address, _value) = get_memory_operand(
                    &_instr.instr.detail.operands()[0].mem,
                    _instr.instr.size,
                    value_size,
                    _analysis,
                    _mem_manager,
                    _state);
                _address = ptr_address;
                _right_destination = _value.abs() as u64;
            },
            _=>{ return (None, None); },
        }
        let mem_type = _mem_manager.get_mem_type(_right_destination as usize);
        match mem_type
        {
            MemoryType::Image=>{
                // push return address to stack
                stack_push(_next_instruction as i64, _mem_manager, _state);
                // add function to function tracker
                
                let func_name = match _analysis.add_func(
                    _state.current_function_addr,
                    _offset,
                    _next_instruction,
                    _address as u64, 
                    _right_destination, 
                    mem_type,
                    false)
                {
                    Some(f)=>f,
                    None=>String::new(),
                };
                if func_name.ends_with("ExitProcess") 
                || func_name.ends_with("Exception") 
                || func_name.ends_with("!_onexit") 
                || func_name.ends_with("!exit") 
                || func_name.ends_with("!_exit")
                {   
                    _analysis.add_return(
                        &_state.current_function_addr,
                        _offset);
                    _left_destination = 0;
                    _right_destination = 0;
                }
                _instr.detail.push(DetailInfo{op_index: 0, contents: func_name });

                let left_analysis: Option<Statex86> = Some(Statex86 
                    {
                        offset: _left_destination as usize,
                        cpu: _state.cpu.clone(), 
                        stack: _state.stack.clone(),
                        current_function_addr: _state.current_function_addr,
                        emulation_enabled: _state.emulation_enabled,
                        loop_state: _state.loop_state.clone(),
                        analysis_type: _state.analysis_type.clone(),
                    });

                let right_analysis: Option<Statex86> = Some(Statex86 
                    {
                        offset: _right_destination as usize,
                        cpu: _state.cpu.clone(), 
                        stack: _state.stack.clone(),
                        current_function_addr: _right_destination,
                        emulation_enabled: _state.emulation_enabled,
                        loop_state: _state.loop_state.clone(),
                        analysis_type: _state.analysis_type.clone(),
                    });
                return (left_analysis, right_analysis);
            },
            _=>{
                //debug!("Call _right_destination @ 0x{:x} 0x{:x}=0x{:x} cur_func 0x{:x}", _offset, _address, _right_destination, _state.current_function_addr);
                let func_name = match _analysis.add_func(
                    _state.current_function_addr,
                    _offset,
                    _left_destination,
                    _address as u64,
                    _right_destination, 
                    MemoryType::Invalid,
                    false)
                {
                    Some(f)=>f,
                    None=>String::new(),
                };

                if func_name.ends_with("ExitProcess") 
                || func_name.ends_with("Exception") 
                || func_name.ends_with("!_onexit") 
                || func_name.ends_with("!exit") 
                || func_name.ends_with("!_exit")
                {   
                    _analysis.add_return(
                        &_state.current_function_addr,
                        _offset);
                    _left_destination = 0;
                    _right_destination = 0;

                }
                _instr.detail.push(DetailInfo{op_index: 0, contents: func_name });

                let left_analysis: Option<Statex86> = Some(Statex86 
                {
                    offset: _left_destination as usize,
                    cpu: _state.cpu.clone(), 
                    stack: _state.stack.clone(),
                    current_function_addr: _state.current_function_addr,
                    emulation_enabled: _state.emulation_enabled,
                    loop_state: _state.loop_state.clone(),
                     analysis_type: _state.analysis_type.clone(),
                });
                return (left_analysis, None);
            },
        }
    }
    return (None, None);
}

pub fn check_branch_instructions(
    _offset: u64, 
    _instr: &mut InstructionInfo, 
    _analysis: &mut Analysisx86,
    _mem_manager: &mut MemoryManager,
    _state: &mut Statex86) -> (Option<Statex86>, Option<Statex86>, bool)
{
    //debug!("check_branch_jmp()");
    let mut _next_instruction: u64 = _offset + (_instr.instr.size as u64);
    let mut _left_destination: i64 = 0;
    let mut _right_destination: i64 = 0;

    let index = DISASMX86_OPLOOKUP_MAP[_instr.instr.opcode as usize] as usize;
    let (is_branch, mut _branch_is_taken) = match DISASMX86_OP_MAP[index] {
        //Decrement count; jump short if count ≠ 0
        "loop" =>{
            if _state.cpu.get_register(&(Registersx86::RCX as u8), 0) != 0
            {
                let count = _state.cpu.get_register(&(Registersx86::RCX as u8), 0) - 1;
                _state.cpu.set_register(&(Registersx86::RCX as u8), count);
                (LoopType::Loop, true)
            } else {
                (LoopType::Loop, false)
            }
        },
        //Decrement count; jump short if count ≠ 0 and ZF = 1.
        "loope" =>{
            if _state.cpu.get_register(&(Registersx86::RCX as u8), 0) != 0 &&
                _state.cpu.get_flag(&EFlags::Zero) == 1
            {
                let count = _state.cpu.get_register(&(Registersx86::RCX as u8), 0) - 1;
                _state.cpu.set_register(&(Registersx86::RCX as u8), count);
                (LoopType::Loop, true)
            } else {
                (LoopType::Loop, false)
            }
        },
        //Decrement count; jump short if count ≠ 0 and ZF = 0.
        "loopne" =>{
            if _state.cpu.get_register(&(Registersx86::RCX as u8), 0) != 0 &&
                _state.cpu.get_flag(&EFlags::Zero) == 0
            {
                let count = _state.cpu.get_register(&(Registersx86::RCX as u8), 0) - 1;
                _state.cpu.set_register(&(Registersx86::RCX as u8), count);
                (LoopType::Loop, true)
            } else {
                (LoopType::Loop, false)
            }
        },
        //Jump short if above or equal (CF=0).
        "jae" =>{
            if _state.cpu.get_flag(&EFlags::Carry) == 0
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        //Jump short if above (CF=0 and ZF=0).
        "ja"=>{
            if _state.cpu.get_flag(&EFlags::Carry) == 0 &&
                _state.cpu.get_flag(&EFlags::Zero) == 0
            {
                (LoopType::Branch, true)
            }
            else{
                (LoopType::Branch, false)
            }
        },
        //Jump short if below or equal (CF=1 or ZF=1).
        "jbe"=>{
            if _state.cpu.get_flag(&EFlags::Carry) == 1 ||
                _state.cpu.get_flag(&EFlags::Zero) == 1
            {
                (LoopType::Branch, true)
            }
            else{
                (LoopType::Branch, false)
            }
        },
        //Jump short if below (CF=1).
        "jb"=>{
            if _state.cpu.get_flag(&EFlags::Carry) == 1
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        //Jump short if carry (CF=1)
        "jc"=>{
            if _state.cpu.get_flag(&EFlags::Carry) == 1
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        //Jump short if CX register is 0.
        "jcxz"=>{
            if _state.cpu.get_register(&(Registersx86::CX as u8), 0) == 0
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        //Jump short if ECX register is 0.
        "jecxz"=>{
            if _state.cpu.get_register(&(Registersx86::ECX as u8), 0) == 0
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        "jrcxz"=>{
            if _state.cpu.get_register(&(Registersx86::RCX as u8), 0) == 0
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        //Jump short if equal (ZF=1).
        "je"=>{
            if _state.cpu.get_flag(&EFlags::Zero) == 1
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        //Jump short if greater or equal (SF=OF)
        "jge"=>{
            if _state.cpu.get_flag(&EFlags::Carry) == 1 && _state.cpu.get_flag(&EFlags::Sign) == _state.cpu.get_flag(&EFlags::Overflow)
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        //Jump short if greater (ZF=0 and SF=OF).
        "jg"=>{
            if (_state.cpu.get_flag(&EFlags::Carry) == 1 || _state.cpu.get_flag(&EFlags::Zero) == 0) &&
                _state.cpu.get_flag(&EFlags::Sign) == _state.cpu.get_flag(&EFlags::Overflow)
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        //Jump short if less or equal (ZF=1 or SF≠ OF).
        "jle"=>{
            if (_state.cpu.get_flag(&EFlags::Carry) == 1 || _state.cpu.get_flag(&EFlags::Zero) == 1) &&
                _state.cpu.get_flag(&EFlags::Sign) != _state.cpu.get_flag(&EFlags::Overflow)
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        //Jump short if less (SF≠ OF).
        "jl"=>{
            if _state.cpu.get_flag(&EFlags::Carry) == 1 && _state.cpu.get_flag(&EFlags::Sign) != _state.cpu.get_flag(&EFlags::Overflow)
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        //Jump short if not equal (ZF=0).
        "jne"=>{
            if _state.cpu.get_flag(&EFlags::Zero) == 0
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        //Jump short if not overflow (OF=0).
        "jno"=>{
            if _state.cpu.get_flag(&EFlags::Overflow) == 0
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        //Jump short if not parity (PF=0).
        "jnp"=>{
            if _state.cpu.get_flag(&EFlags::Parity) == 0
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        //Jump short if not sign (SF=0).
        "jns"=>{
            if _state.cpu.get_flag(&EFlags::Sign) == 0
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        //Jump short if overflow (OF=1).
        "jo"=>{
            if _state.cpu.get_flag(&EFlags::Overflow) == 1
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        //Jump short if parity (PF=1).
        "jp"=>{
            if _state.cpu.get_flag(&EFlags::Parity) == 1
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        //Jump short if sign (SF=1).
        "js"=>{
            if _state.cpu.get_flag(&EFlags::Sign) == 1
            {
                (LoopType::Branch, true)
            } else {
                (LoopType::Branch, false)
            }
        },
        "ljmp" |
        "jmp"=>{
            (LoopType::Jump, true)
        },
        _=>(LoopType::Invalid, false),
    };

    // Ignore Invalid
    if is_branch == LoopType::Invalid
    {
        return (None, None, false);
    }

    // if it's not a branch/loop, then there is no next instruction
    match is_branch
    {
        LoopType::Invalid=>return (None, None, false),
        LoopType::Branch | LoopType::Loop =>{
            _left_destination =(_offset as i64) + (_instr.instr.size as i64);
        },
        LoopType::Jump=>{
            _left_destination = 0;
        }
    }
    
    // Get the first operand
    let value_size: usize = _instr.instr.detail.operands()[0].size as usize;
    match _instr.instr.detail.operands()[0].op_type{
        InstrOpTypex86::Reg=>{
            let destination: i64 = _state.cpu.get_register(
                &_instr.instr.detail.operands()[0].reg,
                _instr.instr.size);
            _right_destination = destination; 
        },
        InstrOpTypex86::Imm=>{
            let destination: i64 = _instr.instr.detail.operands()[0].imm;
            _right_destination = destination; 
        },
        InstrOpTypex86::Mem=>{
            let (_address, destination) = get_memory_operand(
                    &_instr.instr.detail.operands()[0].mem,
                    _instr.instr.size,
                    value_size,
                    _analysis,
                    _mem_manager,
                    _state);
            let mem_type = _mem_manager.get_mem_type(destination as usize);
            // Check if this is a jump table for a function call
            let func_name = match _analysis.add_func(
                _state.current_function_addr,
                _offset,
                0,
                _address as u64,
                destination as u64, 
                mem_type,
                true)
            {
                Some(f)=>f,
                None=>String::new(),
            };
            _right_destination = destination;
            if func_name.ends_with("ExitProcess") 
            || func_name.ends_with("Exception") 
            || func_name.ends_with("!_onexit") 
            || func_name.ends_with("!exit") 
            || func_name.ends_with("!_exit")
            {   
                _analysis.add_return(
                    &_state.current_function_addr,
                    _offset);
                _left_destination = 0;
                _right_destination = 0;
            } else if !func_name.is_empty() {
                _analysis.add_return(
                    &_state.current_function_addr,
                    _offset);
            }
            _instr.detail.push(DetailInfo{op_index: 0, contents: func_name });
            
        },
        _=>return (None, None, false),
    }

    // Add jump to the function jump table
    _analysis.add_jump(
        &_state.current_function_addr,
        _offset,
        _left_destination,
        _right_destination);

    // Check the destination
    let mem_type = _mem_manager.get_mem_type(_right_destination as usize);
    // Only jump in image range for now
    match mem_type
    {
        MemoryType::Image=>{},
        _=>{
            // fall through, Jump is invalid but will be processed anyways
            return (None, None, false);
        }
    }

    // return the jump state
    let mut new_loop_state = _state.loop_state.clone();

    if _state.emulation_enabled{
    	propogate_loop(
        &is_branch,
        &_offset,
        &_next_instruction,
        &mut _branch_is_taken,
        &mut _left_destination,
        &mut _right_destination,
        _mem_manager,
        _state);
    	new_loop_state = _state.loop_state.clone();
        //debug!("\t0x{:x} {:?} LEFT: 0x{:x}, RIGHT: 0x{:x}, taken: {} LOOP: {}", 
        //	_offset, is_branch, 
        //	_left_destination, 
        //	_right_destination, 
        //	_branch_is_taken, 
        //	_state.loop_state.is_loop);
    }
    
    let left_analysis: Option<Statex86> = Some(Statex86 
        {
            offset: _left_destination as usize,
            cpu: _state.cpu.clone(), 
            stack: _state.stack.clone(),
            current_function_addr: _state.current_function_addr,
            emulation_enabled: _state.emulation_enabled,
            loop_state: new_loop_state,
            analysis_type: _state.analysis_type.clone(),
        });

    let right_analysis: Option<Statex86> = Some(Statex86 
        {
            offset: _right_destination as usize,
            cpu: _state.cpu.clone(), 
            stack: _state.stack.clone(),
            current_function_addr: _state.current_function_addr,
            emulation_enabled: _state.emulation_enabled,
            loop_state: _state.loop_state.clone(),
            analysis_type: _state.analysis_type.clone(),
        });
        
    return (left_analysis, right_analysis, _branch_is_taken);
}

pub fn check_return(
    _offset: u64, 
    _instr: &mut InstructionInfo, 
    _analysis: &mut Analysisx86,
    _mem_manager: &mut MemoryManager,
    _state: &mut Statex86) -> (bool, Option<Statex86>)
{
    let index = DISASMX86_OPLOOKUP_MAP[_instr.instr.opcode as usize] as usize;
    match DISASMX86_OP_MAP[index] {
        "int"=>{
            let value: i64 = match _instr.instr.detail.operands()[0].op_type{
                InstrOpTypex86::Imm=>_instr.instr.detail.operands()[0].imm,
                _=>0,
            };

            if value == 0x80 && _state.cpu.get_register(&(Registersx86::EAX as u8), 0) == 1
            {
                // add return to function info
                _analysis.add_return(
                    &_state.current_function_addr,
                    _offset);
                if _state.current_function_addr != 0{
                    _instr.detail.push(
                        DetailInfo
                        {
                            op_index: 0, 
                            contents: format!("FUNC 0x{:x} END", &_state.current_function_addr)
                        });
                }
                return (true, None);
            }
        },
        "int3"=>{
            // add return to function info
            _analysis.add_return(
                &_state.current_function_addr,
                _offset);
            
            return (true, None);
            
        },
        "syscall" |
        "sysret" |
        "sysexit" => {
            //debug!("return");
            // add return to function info
            _analysis.add_return(
                &_state.current_function_addr,
                _offset);

            if _state.current_function_addr != 0{
                _instr.detail.push(
                    DetailInfo
                    {
                        op_index: 0, 
                        contents: format!("FUNC 0x{:x} END", &_state.current_function_addr)
                    });
            }
            return (true, None)
        } 
        "retf" |
        "retfq" |
        "iret" |
        "iretd" |
        "iretq" |
        "ret"=>{
            let value = stack_pop(_mem_manager, _state );
            if _state.current_function_addr != 0{
                _instr.detail.push(
                    DetailInfo
                    {
                        op_index: 0, 
                        contents: format!("FUNC 0x{:x} END", &_state.current_function_addr)
                    });
            }
            
            // add return to function info
            let (is_returned, calling_func) = _analysis.add_return_value(
                value as u64,
                &_state.current_function_addr,
                _offset);

            if is_returned
            {
                //debug!("returning to 0x{:x} @ 0x{:x} calling_func: 0x{:x}", value, _offset, calling_func);
                let mem_type = _mem_manager.get_mem_type(value as usize);
                match mem_type
                {
                    MemoryType::Image=>{
                        let right_analysis: Option<Statex86> = Some(Statex86 
                        {
                            offset: value as usize,
                            cpu: _state.cpu.clone(), 
                            stack: _state.stack.clone(),
                            current_function_addr: calling_func,
                            emulation_enabled: _state.emulation_enabled,
                            loop_state: _state.loop_state.clone(),
                            analysis_type: _state.analysis_type.clone(),
                        });
                        return (true, right_analysis);
                    }
                    _=>{},
                }
            } 
            return (true, None);
        },  
        _=>{},
    }
    return (false, None);
}

pub fn emulate_instructions(
    offset: u64, 
    instr: &mut InstructionInfo, 
    analysis: &mut Analysisx86,
    mem_manager: &mut MemoryManager,
    state: &mut Statex86)
{
    check_binary_arithmetic_instructions(
        offset, 
        instr, 
        analysis,
        mem_manager,
        state);
    check_logical_instructions(
        offset, 
        instr, 
        analysis,
        mem_manager,
        state);
    check_shift_rotate_instructions(
        offset, 
        instr, 
        analysis,
        mem_manager,
        state);
    check_bitbyte_instructions(
        offset, 
        instr, 
        analysis,
        mem_manager,
        state);
    check_misc_instructions(
        offset, 
        instr, 
        analysis,
        mem_manager,
        state);
    check_control_transfer_instructions(
        offset, 
        instr, 
        analysis,
        mem_manager,
        state);
}

// TODO:
// Decimal Arithmetic Instructions
// Control Transfer Instructions
// String Instructions
// I/O Instructions
// 10 Flag Control (EFLAG) Instructions
// Segment Register Instructions
// Miscellaneous Instructions
