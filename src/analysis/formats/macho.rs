use nom::{IResult, InputLength,le_i32, le_u32};
pub fn macho_header(input: &[u8]) -> IResult<&[u8], MachoHeader>
{
    do_parse!(input,
      magic: le_u32 >>
      cputype: le_i32 >>
      cpusubtype: le_i32 >>
      filetype: le_u32 >>
      ncmds: le_u32 >>
      sizeofcmds: le_u32 >>
      flags: le_u32 >>
     ( MachoHeader {
         magic:magic,
         cputype:cputype,
         cpusubtype:cpusubtype,
         filetype:filetype,
         ncmds:ncmds,
         sizeofcmds:sizeofcmds,
         flags:flags
     })
    )
}
#[derive(Debug,Serialize,Deserialize)]
pub struct MachoHeader {
    pub magic: u32,
    pub cputype: i32,
    pub cpusubtype: i32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
}
