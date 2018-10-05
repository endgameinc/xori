//signature_analysis.rs

use configuration::Config;
use analysis::analyze::BinaryType;
use disasm::Arch;
use disasm::Mode;
use regex::bytes::Regex;
use regex::Regex as StrRegex;
use regex::Captures;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::fs::File;
use glob::glob;
//use crc::crc16;

pub struct Signature<'a>{
    pub name: &'static str,
    pub pattern: &'a[&'static str],
}

#[derive(Debug, Clone)]
pub enum RefKind {
    Local,
    Reference
}

#[derive(Debug, Clone)]
pub struct FlirtMatch {
    pub refcount: usize, // could safely drop to u8 I hope
    pub name: String,
    pub offset: usize // doubled 
}

#[derive(Debug, Clone)]
pub struct FlirtRef {
    pub name: String,
    pub offset: usize,
    pub refkind: RefKind,
    pub public: bool, // has trailing @
}

#[derive(Debug)]
pub struct FlirtSignature{
    pub name: String,
    pub pattern: Regex,
    pub refcount: usize,
    pub crc16_len: usize,
    pub sig_crc16: u16,
    pub total_length: usize,
    pub offset: usize,
    pub references: Vec<FlirtRef>,
}

static X86_32_PE: [Signature; 4] = [
    Signature{ 
        name: "_standard_func_header", 
        pattern: &[
            r"\x55\x8B\xEC", //push ebp, mov ebp, esp
            r"\x55\x89\xE5", //push ebp, mov ebp, esp
        ], 
    },
    Signature{ 
        name: "_non_standard_func_header", 
        pattern: &[
            // push ebp
            // push esp
            // pop ebp
            r"\x55\x54\x5D", 
            // sub dword ptr [esp+4], 33h
            r"\x81\x6C\x24", 
            // push -1
            // push offset SEH_402F80
            r"\x6A.\x68..[\x40-\x4F]\x00",
            // mov     edx, [esp+arg_4]
            // push    esi 
            r"\x8B..\x56",
            r"\x8B..\x56",
            // push    esi
            // push    edi
            // mov esi, ecx
            r"\x56\x57\x8B[\x00-\xFF]",
            // push    esi
            // mov     esi, ecx
            r"\x56\x8B\xF1",
            // push    ebx
            // push    esi
            // mov     esi, ecx
            r"\x53\x56\x8B\xF1",
            // push    ebx
            // push    ecx
            // push    ebx
            // lea
            r"\x53\x51\x53\x8D",
            // mov     eax, offset off_419448
            r"[\xB8-\xBF]..[\x40-\x4F]\x00",
            // mov     eax, large fs:0
            r"\x64\xA1\x00\x00\x00",
        ], 
    },
    Signature{ 
        name: "_null_func", 
        pattern: &[
            // xor     eax, eax
            // ret 4
            r"\x33\xC0\xC2.\x00", 
        ], 
    },
    Signature{ 
        name: "_possible_function_jump", 
        pattern: &[
            r"\x55\xE9..[\x40-\x4F]\x00", //push ebp, jmp
            r"\xE9[\x01-\xFF]\x00\x00\x00", // jmp short
        ], 
    },
];

static X86_64_PE: [Signature; 2] = [
    Signature{ 
        name: "_standard_func_header", 
        pattern: &[
            r"\x48\x89\x5C\x24.\x48\x89\x74\x24.", //mov QWORD PTR [rsp+0x8],rbx, mov QWORD PTR [rsp+0x10],rsi
            r"\x40\x53\x48\x83\xEC.", //push rbx, sub rsp, 60h
            r"\x48\x83\xEC..", //sub rsp, 28h
            r"\x48\x89\x5C\x24.", //mov [rsp+arg_8],rbx 
            r"\x48\x81\xEC....", //sub rsp, 168h,
            r"\xFF\xF5\x41\x54\x41\x55\x41\x56", //push rbp, push r12, push r13, push r14
            r"\x45\x33\xD2", //xor r10d, r10d
            r"\x45\x85\xC9", // test r9d, r9d
            r"\x48\x85\xC9", //test    rcx, rcx
            r"\x4C..\x53\x57\x48\x81....", //  mov r11, rsp, push rbx, push rdi, sub rsp, 118h
            r"\x4C..\x49...\x56\x48\x81....", //mov, mov, push, sub rsp
            r"\xff\xf3\x48\x83.." //push rbx, sub rsp
        ],
    },
    Signature{ 
        name: "_possible_function_jump", 
        pattern: &[
            r"\xFF\x25..\x00\x00", //  jmp QWORD PTR [rip+0x8a2]
        ],
    },
];

pub struct SigAnalyzer
{
    pub signatures: BTreeMap<String, Vec<&'static str>>,
    pub flirts: BTreeMap<String, FlirtSignature>,
    full_signatures_regex: Regex
}

impl SigAnalyzer
{
    pub fn new()->SigAnalyzer {
        SigAnalyzer{
            signatures: BTreeMap::new(),
            flirts: BTreeMap::new(),
            full_signatures_regex: Regex::new("").unwrap()
        }
    }
    pub fn init(&mut self, cfg: &Config, arch: &Arch, mode: &Mode, btype: &BinaryType,)
    {
        match *arch
        {
            Arch::ArchX86=>{
                match (*btype, *mode)
                {
                    (BinaryType::PE, Mode::Mode16)=>{

                    },
                    (BinaryType::PE, Mode::Mode32)=>{
                        if cfg.x86.flirt_enabled {
                            self.load_flirts(&cfg.x86.pe_file.flirt_pat_glob32);
                            self.load_internal_flirts(btype, mode);
                        }
                        for sig in X86_32_PE.iter()
                        {
                            self.signatures.insert(String::from(sig.name), sig.pattern.to_vec());
                        }
                    },
                    (BinaryType::PE, Mode::Mode64)=>{
                        if cfg.x86.flirt_enabled {
                            self.load_flirts(&cfg.x86.pe_file.flirt_pat_glob64);
                            self.load_internal_flirts(btype, mode);
                        }
                        for sig in X86_64_PE.iter()
                        {
                            self.signatures.insert(String::from(sig.name), sig.pattern.to_vec());
                        }
                    },
                    _=>{},
                };

                // now precompile the list of all signatures
                let mut regex = r"(?-u)".to_string();

                for (name, sigs) in self.signatures.iter() {
                    regex += &format!("(?P<{}>",name);
                    for (i, sig) in sigs.iter().enumerate() {
                        if sigs.len() == i + 1 {
                            regex += &format!("{})|", sig);
                        } else {
                            regex += &format!("{}|", sig);
                        }
                    }
                }
                regex = regex.trim_right_matches("|").to_string();
                self.full_signatures_regex = Regex::new(&regex).unwrap();
            },
            _=>{},
        }
    }
    pub fn load_flirts(&mut self, pat_glob: &String) {
        let mut pattern;
        let mut nontemp;
        // <leading bytes> <CRC16 len> <CRC16> <total length> <public name(s)> <referenced name(s)> <tailing bytes>
        for entry in glob(pat_glob).expect("Failed to read glob pattern") {
            match entry {
                Ok(path) => {
                    let reader = BufReader::new(File::open(path.display().to_string()).expect("Cannot open file.txt"));
                    for line in reader.lines() {
                        nontemp = line.expect("trouble with .pat file");
                        let v: Vec<_> = nontemp.split(' ').collect();
                        if v.len() < 6 { continue; }
                        let re = StrRegex::new(r"[[:xdigit:]]{2}|\.\.").unwrap();
                        let s = v[0];
                        pattern = Regex::new( (r"(?-u)".to_string() + &re.replace_all(s, |cap: &Captures| {
                            match &cap[0] {
                                ".." => r".".to_string(),
                                x => r"\x".to_string() + x
                            }
                        })).as_str()).unwrap();

                        let marked_offset = &v[4];
                        let offset = usize::from_str_radix(marked_offset.trim_left_matches(':').trim_right_matches('@'), 16).unwrap(); // has special trailing chars and starts with :
                        let mut my_refs = vec![];
                        if v.len() > 6 {
                            for rawref in v[6..].iter().collect::<Vec<_>>().chunks(2) { // keep first ref
                                if rawref.len() < 2 {continue;} // no time for trailing stuff
                                //if
                                //usize::from_str_radix((rawref[0]).trim_left_matches('^').trim_left_matches(':').trim_right_matches('@'),
                                //16).unwrap() > 0x8000 { continue; } // bold play to try and keep
                                //within bounds // this may be necessary again to make sure we
                                //don't step over the bounds of the binary
                                let mut flirtref = FlirtRef {
                                    offset: usize::from_str_radix((rawref[0]).trim_left_matches('^').trim_left_matches(':').trim_right_matches('@'), 16).unwrap(),
                                    refkind: match rawref[0].chars().next().unwrap() {
                                        ':' => RefKind::Local,
                                        _ => RefKind::Reference,
                                    },
                                    public: rawref[0].ends_with('@'),
                                    name: rawref[1].to_string(),
                                };
                                my_refs.push(flirtref);
                                //break; // add back if you just want to try the first listed
                                //reference
                            }
                        }
                        let flirtsig = FlirtSignature {
                            name: v[5].to_string(),
                            pattern: pattern,
                            refcount: my_refs.len(),
                            crc16_len: usize::from_str_radix(v[1],16).unwrap(),
                            sig_crc16: u16::from_str_radix(v[2],16).unwrap(),
                            total_length: usize::from_str_radix(v[3],16).unwrap(),
                            offset: offset,
                            references: my_refs,
                        };
                        
                        self.flirts.insert( v[5].to_string(), flirtsig);
                    }
                    
                },
                Err(e) => println!("{:?}", e),
            }
        }
    }

    pub fn flirt_match(&self, bytes:&[u8]) -> BTreeMap<String,Vec<usize>> 
    {
        let mut known: BTreeMap<usize, FlirtMatch> = BTreeMap::new();
        let mut unknown: BTreeMap<usize, Vec<FlirtMatch>> = BTreeMap::new();
        // superunknown = joke variable name for clone of unknown that gets mutated
        let mut _superunknown: BTreeMap<usize, Vec<FlirtMatch>> = BTreeMap::new();
        let mut _last_known_len = 0;
        loop { 
            _last_known_len = known.len();
            if _last_known_len == 0 {
                for (name, flirtsig) in self.flirts.iter() {
                    debug!("flirt_match: SIG: {}", name);
                    for mat in flirtsig.pattern.find_iter(bytes) { // can use find iter, because no named groups
                        //if flirtsig.sig_crc16 == crc16::checksum_usb(&bytes[32..32+flirtsig.crc16_len]) {
                            let fm = FlirtMatch {
                                refcount: flirtsig.refcount,
                                name: name.to_string(),
                                offset: mat.start(),
                            };
                            if fm.refcount == 0 {
                                known.insert(mat.start(),fm);
                            } else {
                                unknown.entry(mat.start()).or_insert(vec![]).push(fm);
                            }
                        //}
                    }
                } // all sigs
            }
            if known.len() == 0 { break } // no ground truth give up early
            _superunknown = unknown.clone();
            for (_offset, fmvec) in unknown.iter() {
                for (ind_fm, fm) in fmvec.iter().enumerate() {
                    for sigref in &self.flirts.get(&fm.name).unwrap().references {
                        if known.contains_key(&(fm.offset + sigref.offset)) {
                            let mut xs = _superunknown.get_mut(&(fm.offset)).unwrap();
                            if xs[ind_fm].refcount == 0 {
                                known.insert(fm.offset,fm.clone());
                                xs.remove(ind_fm);
                            } else  {
                                xs[ind_fm].refcount -= 1;
                            }
                        }
                    }
                }
            }
            unknown = _superunknown;
            if known.len() == _last_known_len {break} // in other words if we stopped learning new connections give up
        } // while unknown
        let mut sig_to_offsets = BTreeMap::new();
        for (_,fm) in known.iter() {
            sig_to_offsets.insert(fm.name.to_string(),vec![]);
        }
        for (offset,fm) in known.iter() {
            sig_to_offsets.entry(fm.name.to_string()).and_modify(|v| {v.push(*offset)});
        }
        return sig_to_offsets;
    }

    pub fn match_bytes(&self, bytes:&[u8])-> BTreeMap<String,Vec<usize>>
    {
        let mut sig_to_offsets = BTreeMap::new();
        for (k, _v) in self.signatures.iter() {
            sig_to_offsets.insert(k.to_string(),vec![]);
        }
        for cap in self.full_signatures_regex.captures_iter(&bytes) {
            for (k, _v) in self.signatures.iter() {
                match cap.name(k) {
                    Some(m) => {sig_to_offsets.entry(k.to_string()).and_modify(|v| {v.push(m.start())});},
                          _ => ()
                }
            }
        }
        return sig_to_offsets;
    }
    pub fn match_by_sig(&self, sig_name: &String, bytes:&[u8])-> Vec<usize>
    {
        let mut sig_to_offsets: Vec<usize> = Vec::new();
        let mut regex = r"(?-u)".to_string();

        match self.signatures.get(sig_name)
        {
            Some(sigs)=>{
                regex += &format!("(?P<{}>",sig_name);
                for (i, sig) in sigs.iter().enumerate() {
                    if sigs.len() == i + 1 {
                        regex += &format!("{})|", sig);
                    } else {
                        regex += &format!("{}|", sig);
                    }
                }
                regex = regex.trim_right_matches("|").to_string();
                let re = Regex::new(&regex).unwrap();
                for cap in re.captures_iter(&bytes) {
                    match cap.name(sig_name) {
                        Some(m)=>{
                            sig_to_offsets.push(m.start());
                        },
                        _=>{},
                    }
                }
            },
            None=>{}
        }
        return sig_to_offsets;
    }

    pub fn load_internal_flirts(&mut self, btype: &BinaryType, mode: &Mode)
    {
        println!("LOADING INTERNAL FLIRT SIGNATURES");
        match (*btype, *mode)
        {
            (BinaryType::PE, Mode::Mode32)=>{
                let mut x86_32_pe_msvc: BTreeMap<String, FlirtSignature> = BTreeMap::new();
                x86_32_pe_msvc.insert(
                    String::from("_WinMain_0"),
                    //MSVC
                    FlirtSignature{ 
                        name: String::from("_WinMain"), 
                        // push eax
                        // push esi
                        // push ebx
                        // push ebx
                        // call [0x40a0ac]  ;kernel32.dll!GetModuleHandleA
                        // push eax
                        // call 0x408140 ; WinMain
                        pattern: Regex::new(r"(?-u)\x50\x56\x53\x53\xFF\x15..[\x40-\x4F]\x00\x50\xE8....").unwrap(),
                        refcount: 0,
                        crc16_len: 0,
                        sig_crc16: 0,
                        total_length: 15,
                        offset: 0,
                        references: vec![
                            FlirtRef {
                                offset: 11,
                                refkind: RefKind::Local,
                                public: true,
                                name: String::from("_WinMain"),
                            }
                        ], 
                    });
                x86_32_pe_msvc.insert(
                    String::from("_WinMain_1"),
                    FlirtSignature{ 
                        name: String::from("_WinMain"), 
                            // push eax
                            // push [ebp+lpCmdLine] 
                            // push esi
                            // push esi
                            // call [0x40a0ac]  ;kernel32.dll!GetModuleHandleA
                            // push eax
                            // call 0x408140 ; WinMain
                        pattern: Regex::new(r"(?-u)\x50\xFF\x75\x9C\x56\x56\xFF\x15..[\x40-\x4F]\x00\x50\xE8....").unwrap(),
                        refcount: 0,
                        crc16_len: 0,
                        sig_crc16: 0,
                        total_length: 17,
                        offset: 0,
                        references: vec![
                            FlirtRef {
                                offset: 13,
                                refkind: RefKind::Local,
                                public: true,
                                name: String::from("_WinMain"),
                            }
                        ], 
                    });
                x86_32_pe_msvc.insert(
                    String::from("_main_0"),
                    // CRT
                    FlirtSignature{ 
                        name: String::from("_main"), 
                            //call    __p___wargv
                            //mov     edi, eax
                            //call    __p___argc
                            //mov     esi, eax
                            //call    _get_initial_wide_environment
                            //push    eax             ; envp
                            //push    dword ptr [edi] ; argv
                            //push    dword ptr [esi] ; argc
                            //call    _main
                        pattern: Regex::new(r"(?-u)\xE8..\x00\x00\x8B\xF8\xE8..\x00\x00\x8B\xF0\xE8..\x00\x00\x50\xFF\x37\xFF\x36\xE8....").unwrap(),
                        refcount: 0,
                        crc16_len: 0,
                        sig_crc16: 0,
                        total_length: 29,
                        offset: 0,
                        references: vec![
                            FlirtRef {
                                offset: 0,
                                refkind: RefKind::Local,
                                public: true,
                                name: String::from("__p___wargv"),
                            },
                            FlirtRef {
                                offset: 7,
                                refkind: RefKind::Local,
                                public: true,
                                name: String::from("__p___argc"),
                            },
                            FlirtRef {
                                offset: 14,
                                refkind: RefKind::Local,
                                public: true,
                                name: String::from("_get_initial_wide_environment"),
                            },
                            FlirtRef {
                                offset: 24,
                                refkind: RefKind::Local,
                                public: true,
                                name: String::from("_main"),
                            }
                        ], 
                    });
                 x86_32_pe_msvc.insert(
                    String::from("_main_1"),
                    FlirtSignature{ 
                        name: String::from("_main"),
                        //A1 D0 32 4A 00          mov     eax, envp
                        //A3 F0 32 4A 00          mov     dword_4A32F0, eax
                        //50                      push    eax             ; envp
                        //FF 35 C8 32 4A 00       push    argv            ; argv
                        //FF 35 C4 32 4A 00       push    argc            ; argc
                        //E8 49 33 FD FF          call    _main 
                        pattern: Regex::new(r"(?-u)\xA1....\xA3....\x50\xFF\x35....\xFF\x35....\xE8....").unwrap(),
                        refcount: 0,
                        crc16_len: 0,
                        sig_crc16: 0,
                        total_length: 27,
                        offset: 0,
                        references: vec![
                            FlirtRef {
                                offset: 23,
                                refkind: RefKind::Local,
                                public: true,
                                name: String::from("_main"),
                            }
                        ], 
                    });
                self.flirts.append(&mut x86_32_pe_msvc);
            }
            _=>{},
        }
    }
}
