//test.rs
use colored::*;
pub use disasm::*;
use arch::x86::archx86::*;
use arch::x86::displayx86::*;
use std::fmt::Write;
use std::fmt::Debug;

//use configuration::Config;
use disasm::Mode;
use analysis::signature_analysis::SigAnalyzer;

#[cfg(test)]
fn hex_array(arr: &[u8]) -> String {
    let mut s = String::new();
    for &byte in arr {
        write!(&mut s, "{:02X} ", byte).expect("Unable to write");
    }
    return s;
}

#[cfg(test)]
fn print_instruction<T: ArchDetail + Debug>(_instructions: &mut Instruction<T>)
{
    println!("\t\t\t{} {}", _instructions.mnemonic, _instructions.op_str);
    println!("\tbytes: {}", hex_array(&_instructions.bytes));
    println!("\tprefix: {}", hex_array(_instructions.detail.prefix()));
    println!("\topcode: {}", hex_array(_instructions.detail.opcode()));
    println!("\taddress_size: {}", *_instructions.detail.address_size());
    if *_instructions.detail.mod_rm() > 0 {
        println!("\tmod_rm: 0x{:x}", *_instructions.detail.mod_rm());
    }
    if *_instructions.detail.rex() > 0 {
        println!("\trex: 0x{:x}", *_instructions.detail.rex());
    }
    if *_instructions.detail.displacement() > 0 {
        println!("\tdisp: 0x{:x}", *_instructions.detail.displacement());
    }
    let mut index = 0;
    while index < *_instructions.detail.op_count(){
        println!("\t\toperands[{}].op_type = {:?}", index, _instructions.detail.operands()[index].op_type);
        match _instructions.detail.operands()[index].op_type{
            InstrOpTypex86::Reg=>{ 
                println!("\t\toperands[{}].reg = {}", index, print_register(_instructions.detail.operands()[index].reg as usize));
                println!("\t\toperands[{}].size = {}", index, _instructions.detail.operands()[index].size);
            },
            InstrOpTypex86::Imm=>{
                println!("\t\toperands[{}].imm = 0x{:x}", index, _instructions.detail.operands()[index].imm);
                println!("\t\toperands[{}].size = {}", index, _instructions.detail.operands()[index].size);
            },
            InstrOpTypex86::Mem=>{
                if _instructions.detail.operands()[index].mem.segment > 0{
                    println!("\t\toperands[{}].mem.segment = {}", index, print_register(_instructions.detail.operands()[index].mem.segment as usize));
                }
                if _instructions.detail.operands()[index].mem.base > 0{
                    println!("\t\toperands[{}].mem.base = {}", index, print_register(_instructions.detail.operands()[index].mem.base as usize));
                }
                if _instructions.detail.operands()[index].mem.index > 0{
                    println!("\t\toperands[{}].mem.index = 0x{:x}", index, _instructions.detail.operands()[index].mem.index);
                }
                if _instructions.detail.operands()[index].mem.scale > 0{
                    println!("\t\toperands[{}].mem.scale = 0x{:x}", index, _instructions.detail.operands()[index].mem.scale);
                }
                if _instructions.detail.operands()[index].mem.displacement > 0{
                    println!("\t\toperands[{}].mem.displacement = 0x{:x}", index, _instructions.detail.operands()[index].mem.displacement);
                }
                println!("\t\toperands[{}].size = {}", index, _instructions.detail.operands()[index].size);
            },
            _=>{},
        }
        index+=1;
    }
}

#[cfg(test)]
struct CodeTest<'a>{
    code: &'a[u8],
    mode: Mode,
    result: bool,
    nmemonic: &'static str,
}
#[cfg(test)]
struct SizeTest<'a>{
    code: &'a[u8],
    mode: Mode,
    result: bool,
    size: u8,
}

const UADDRESS: usize = 0x1000;

#[cfg(test)]
fn x86_test(address: usize, test: &CodeTest)->bool{

	let xi = Xori { arch: Arch::ArchX86, mode: Mode::Mode32 };
	let xi64 = Xori { arch: Arch::ArchX86, mode: Mode::Mode64 };
    let mut _result = false;
    let mut vec: Vec<Instruction<X86Detail>> = Vec::new();
    
    if test.mode == Mode::Mode32 {
        xi.disasm(test.code, test.code.len(), address, address, 0, &mut vec);
    }
    else if test.mode == Mode::Mode64
    {
        xi64.disasm(test.code, test.code.len(), address, address, 0, &mut vec);
    }
    if vec.len() > 0
    {
        let test_string = format!("{} {}", vec[0].mnemonic, vec[0].op_str);
        if (test_string == String::from(test.nmemonic)) == test.result{
            println!("{} bytes: {:32}", "[PASS] ".green(), hex_array(test.code));
            _result = true;
        } 
        else 
        {
            println!("{} bytes: {:32}", "[FAIL] ".red(), hex_array(test.code));
            _result = false;
        }
    } else if !(vec.len() == 0) == test.result {
        println!("{} bytes: {:32}", "[PASS] ".green(), hex_array(test.code));
        _result = true;
    }
    else
    {
        println!("{} bytes: {:32}", "[FAIL] ".red(), hex_array(test.code));
        _result = false;
    }
    for mut item in vec.iter_mut(){
        print_instruction(&mut item);
    }
    return _result;
}

#[cfg(test)]
fn x86_size(address: usize, test: &SizeTest)->bool{

    let xi = Xori { arch: Arch::ArchX86, mode: Mode::Mode32 };
    let xi64 = Xori { arch: Arch::ArchX86, mode: Mode::Mode64 };
    let mut _result = false;
    let mut vec: Vec<Instruction<X86Detail>> = Vec::new();
    
    if test.mode == Mode::Mode32 {
        xi.disasm(test.code, test.code.len(), address, address, 0, &mut vec);
    }
    else if test.mode == Mode::Mode64
    {
        xi64.disasm(test.code, test.code.len(), address, address, 0, &mut vec);
    }
    if vec.len() > 0
    {
        if (vec[0].detail.operands()[0].size == test.size) == test.result{
            println!("{} bytes: {:32}", "[PASS] ".green(), hex_array(test.code));
            _result = true;
        } 
        else 
        {
            println!("{} bytes: {:32}", "[FAIL] ".red(), hex_array(test.code));
            _result = false;
        }
    } else if !(vec.len() == 0) == test.result {
        println!("{} bytes: {:32}", "[PASS] ".green(), hex_array(test.code));
        _result = true;
    }
    else
    {
        println!("{} bytes: {:32}", "[FAIL] ".red(), hex_array(test.code));
        _result = false;
    }
    for mut item in vec.iter_mut(){
        print_instruction(&mut item);
    }
    return _result;
}
#[test]
fn prefix_rep() {
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\xf3\xaa", mode: Mode::Mode32, result: true, nmemonic: "rep stosb es:[edi], al"}));
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\xf3\xab", mode: Mode::Mode32, result: true, nmemonic: "rep stosd es:[edi], eax"}));
}
#[test]
fn prefix_lock() {
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\xF0\x41", mode: Mode::Mode32, result: true, nmemonic: "lock inc ecx"}));
}
#[test]
fn nop_xchg_pause() {
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x41\x90", mode: Mode::Mode64, result: true, nmemonic: "xchg eax, r8d"})); //xchg   r8d,eax (64bit only)
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\xf2\x90", mode: Mode::Mode32, result: true, nmemonic: "nop "}));//repnz nop
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x67\x66\x90", mode: Mode::Mode32, result: true, nmemonic: "xchg ax, ax"})); // xchg ax,ax (xchg not noop)
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x90", mode: Mode::Mode32, result: true, nmemonic: "nop "}));
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\xf3\x90", mode: Mode::Mode32, result: true, nmemonic: "pause "}));
}
#[test]
fn instruction_3dnow() {
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x0F\x0F\xC1\x0D", mode: Mode::Mode32, result: true, nmemonic: "pi2fd mm0, mm1"}));//pi2fd  mm0,mm1 (test 3dNow!)
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x0F\x0F\xC0\x0D", mode: Mode::Mode32, result: true, nmemonic: "pi2fd mm0, mm0"}));//pi2fd  mm0,mm0 (test 3dNow!)
}
#[test]
fn femms() {
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x0F\x0E", mode: Mode::Mode32, result: true, nmemonic: "femms "})); //femms (test 3dNow!)
}
#[test]
fn register_segment() {
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x64\xa3\x00\x00\x00\x00", mode: Mode::Mode32, result: true, nmemonic: "mov fs:[0x0], eax"}));
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x65\x89\x1D\x00\x00\x00\x00", mode: Mode::Mode32, result: true, nmemonic: "mov gs:[0x0], ebx"}));
}
#[test]
fn lds_86_64(){
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x67\x66\xC5\x44\x17", mode: Mode::Mode32, result: true, nmemonic: "lds ax, [si+0x17]"}));
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x67\x66\xC5\x44\x17", mode: Mode::Mode64, result: false, nmemonic: "lds ax, [si+0x17]"}));
}
#[test]
fn prefix_vex(){
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x62\xC1\x6D\x48\x62\xCB", mode: Mode::Mode32, result: true, nmemonic: "vpunpckldq zmm1, zmm2, zmm3"}));
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x62\xC1\x6D\x48\x62\xCB", mode: Mode::Mode64, result: true, nmemonic: "vpunpckldq zmm17, zmm2, zmm11"}));
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\xC4\xE3\x7D\x4B\xEA\x40", mode: Mode::Mode32, result: true, nmemonic: "vblendvpd ymm5, ymm0, ymm2, ymm4"}));
}
#[test]
fn memory_operand(){
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x67\x66\xC4\x44\x17", mode: Mode::Mode32, result: true, nmemonic: "les ax, [si+0x17]"}));
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x67\x66\x0F\xB5\x44\x17", mode: Mode::Mode32, result: true, nmemonic: "lgs ax, [si+0x17]"}));
}
#[test]
fn sib_encoding_vvvv(){
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x33\x04\x00", mode: Mode::Mode32, result: true, nmemonic: "xor eax, [eax+eax*0x1]"}));
}
#[test]
fn encoding_ib(){
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x93", mode: Mode::Mode32, result: true, nmemonic: "xchg eax, ebx"}));
}
#[test]
fn encoding_writemask(){
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x24\xFC", mode: Mode::Mode32, result: true, nmemonic: "and al, 0xfc"}));
}
#[test]
fn mod_rm_64bit(){
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x03\x15\x00\x00\x00\x01", mode: Mode::Mode64, result: true, nmemonic: "add edx, [rip+0x1000000]"}));
}
#[test]
fn add_reg_before_after(){
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x0F\x21\x21", mode: Mode::Mode32, result: true, nmemonic: "mov ecx, dr4"})); //mov ecx,dr4    
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\x31\xC0", mode: Mode::Mode32, result: true, nmemonic: "xor eax, eax"})); //xor eax,eax
}
#[test]
fn jump_calls(){
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\xe3\xf1", mode: Mode::Mode32, result: true, nmemonic: "jecxz 0xff3"})); //jecxz 0xfffffff3 (jecxz addr fixup)
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x66\xE8\x01\x02", mode: Mode::Mode32, result: true, nmemonic: "call 0x1205"})); //callw  0x1205 (with address 0x1000)
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\xFF\xE0", mode: Mode::Mode32, result: true, nmemonic: "jmp eax"})); //jmp eax
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\xE9\xFE\xFF\xFF\xFF", mode: Mode::Mode32, result: true, nmemonic: "jmp 0x1003"})); //jmp -3 <_main+0x3> Relative Jump test
}
#[test]
fn avx_sse(){
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x62\xF1\x7C\xA9\x5D\xD1", mode: Mode::Mode32, result: false, nmemonic: "vminps ymm2 {k1}{z}, ymm0, ymm1"}));//vminps ymm2 {k1}{z}, ymm0, ymm1 AVX Zero Mask
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x62\xF1\x6C\x99\x5D\xCB", mode: Mode::Mode32, result: false, nmemonic: "vminps zmm1{k1}{z}, zmm2, zmm3, {sae}"}));//vminps zmm1{k1}{z},zmm2,zmm3,{sae}
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\xC5\xFE\xE6\xCA", mode: Mode::Mode32, result: true, nmemonic: "vcvtdq2pd ymm1, xmm2"})); //vcvtdq2pd ymm1,xmm2 AVX 2
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\xF2\x0F\xC2\xCA\x10", mode: Mode::Mode32, result: true, nmemonic: "cmpsd xmm1, xmm2, 0x10"})); // cmpeqsd xmm1,xmm2, 16 SSECC case
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\xF2\x0F\xC2\xCA\x07", mode: Mode::Mode32, result: true, nmemonic: "cmpsd xmm1, xmm2, 0x7"})); // cmpordsd xmm1,xmm2, 7 SSECC case
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\xC5\xED\xC2\xCB\x00", mode: Mode::Mode32, result: true, nmemonic: "vcmppd ymm1, ymm2, ymm3, 0x0"}));//vcmpeqpd ymm1,ymm2,ymm3 AVX512
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\x66\x0f\x5d\xca", mode: Mode::Mode64, result: true, nmemonic: "minpd xmm1, xmm2"})); // minpd  xmm1,xmm2  (64bit) //AVX512 displacement
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\xF3\x0F\x10\xC1", mode: Mode::Mode32, result: true, nmemonic: "movss xmm0, xmm1"})); //movss  xmm0,xmm1
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\xF2\x0F\x59\xCA", mode: Mode::Mode32, result: true, nmemonic: "mulsd xmm1, xmm2"})); //mulsd  xmm1,xmm2
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\xF2\x66\x0F\x59\xCA", mode: Mode::Mode32, result: true, nmemonic: "mulsd xmm1, xmm2"})); //mulsd xmm1,xmm2
}
#[test]
fn parse_two_instructions(){
	assert!(x86_test(UADDRESS, &CodeTest{code: b"\xf3\xaa\xF2\x66\x0F\x59\xCA", mode: Mode::Mode32, result: true, nmemonic: "rep stosb es:[edi], al"}));
}

#[test]
fn move_test(){
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\x8c\x55\x28", mode: Mode::Mode32, result: true, nmemonic: "mov [ebp+0x28], ss"}));
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\x66\x89\x45\xe4", mode: Mode::Mode32, result: true, nmemonic: "mov [ebp-0x1c], ax"}));
}

#[test]
fn disp_test(){
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\x89\x95\x36\xff\xff\xff", mode: Mode::Mode32, result: true, nmemonic: "mov [ebp-0xca], edx"}));
}

#[test]
fn reg_size(){
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\x00\xe9", mode: Mode::Mode32, result: true, nmemonic: "add cl, ch"}));
}

#[test]
fn address_test(){
    assert!(x86_test(0xa3, &CodeTest{code: b"\x78\x78", mode: Mode::Mode32, result: true, nmemonic: "js 0x11d"}));
}

#[test]
fn last_op_test(){
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\xD3\xEA", mode: Mode::Mode32, result: true, nmemonic: "shr edx, cl"}));
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\x06", mode: Mode::Mode32, result: true, nmemonic: "push es"}));
}

#[test]
fn push_test(){
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\x68\x28\x10\x40\x00", mode: Mode::Mode32, result: true, nmemonic: "push 0x401028"}));
}

#[test]
fn call_pointer(){
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\xFF\x15\x24\x90\x40\x00", mode: Mode::Mode32, result: true, nmemonic: "call [0x409024]"}));
}

#[test]
fn long_instruction(){
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\xC7\x05\x54\xB4\x40\x00\x16\x00\x00\x00", mode: Mode::Mode32, result: true, nmemonic: "mov [0x40b454], 0x16"}));
}

#[test]
fn mode64_sil()
{
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\x40\x32\xF6", mode: Mode::Mode64, result: true, nmemonic: "xor sil, sil"}));
}

#[test]
fn adc_leave()
{
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\x11\xC9", mode: Mode::Mode32, result: true, nmemonic: "adc ecx, ecx"}));
}

#[test]
fn add_size()
{
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\x00\xE8", mode: Mode::Mode32, result: true, nmemonic: "add al, ch"}));
}

#[test]
fn cmp_byte()
{
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\xA6", mode: Mode::Mode32, result: true, nmemonic: "cmpsb [esi], es:[edi]"}));
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\x80\x3A\x00", mode: Mode::Mode32, result: true, nmemonic: "cmp [edx], 0x0"}));
}

#[test]
fn outsb_byte()
{
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\x6E", mode: Mode::Mode32, result: true, nmemonic: "outsb dx, [esi]"}));
}

#[test]
fn all_size()
{
    assert!(x86_size(UADDRESS, &SizeTest{code: b"\x00\xE8", mode: Mode::Mode32, result: true, size: 1})); //add al, ch
    assert!(x86_size(UADDRESS, &SizeTest{code: b"\x2C\xE8", mode: Mode::Mode32, result: true, size: 1})); //sub al, 0xe8
    assert!(x86_size(UADDRESS, &SizeTest{code: b"\x83\xEE\xFC\x00\x00", mode: Mode::Mode32, result: true, size: 4})); //sub esi, 0xfffffffc
    assert!(x86_size(UADDRESS, &SizeTest{code: b"\x66\x2d\xe8\x00", mode: Mode::Mode32, result: true, size: 2})); //sub ax, 0xe8
    assert!(x86_size(UADDRESS, &SizeTest{code: b"\xFF\x25\xA2\x08\x00\x00", mode: Mode::Mode64, result: true, size: 8}));
    assert!(x86_size(UADDRESS, &SizeTest{code: b"\x66\xF7\x25\xC0\x13\x40\x00", mode: Mode::Mode32, result: true, size: 2}));
}
#[test]
fn mem_print()
{
    assert!(x86_test(UADDRESS, &CodeTest{code: b"\xFF\x24\x05\x00\x46\x6F\x72", mode: Mode::Mode32, result: true, nmemonic: "jmp [eax*0x1+0x726f4600]"}));
}

#[test]
fn flirt_up()
{
    let mut sig_analyzer = SigAnalyzer::new();
    let bytes = [0x55,0x8B,0xEC,0xDC,0xEF,0xCD,0xFD,0x00,0x32,0x12,0x30,0x87,0x82,0x34,0x71,0x28,0x47,0x18,0x48,0x78,0x12,0x74,0x82,0x74,0x81,0x32,0x34,0x45,0x34,0x32,0x34,0x34];
    sig_analyzer.load_flirts(&String::new());
    sig_analyzer.flirt_match(&bytes);
}
