// macholoader.rs]
use configuration::Config;
use analysis::analyze::Header;
use analysis::formats::macho::*;

pub fn get_macho_header(
    header: &mut Header,
    binary: &mut [u8],
    config: &Config) -> Result<i32, String>
{
    debug!("get_macho_header()");
    let macho_offset = match macho_header(&binary)
    {
      Ok((_cursor, o))=>o.sizeofcmds as usize,
      Err(_)=>return Err(String::from("Error incomplete MACHO Header")),
    };
    if macho_offset > binary.len()
    {
        return Err(String::from("Error incomplete MACHO Header"));
    }
    return Ok(0);
}
