extern crate num;
extern crate colored;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate bincode;
extern crate memmap;
extern crate encoding;
extern crate regex;
extern crate glob;
extern crate crc;

#[macro_use]
extern crate nom;
pub mod disasm;
pub mod configuration;
#[macro_use]
pub mod log;
#[cfg(test)]
pub mod test;

pub mod arch
{
    pub mod x86
    {
        #[macro_use]
        pub mod archx86;
        pub mod registersx86;
        pub mod instructionsx86;
        pub mod prefixx86;
        pub mod disasmtablesx86;
        pub mod opcodex86;
        pub mod operandx86;
        pub mod displayx86;
        pub mod cpux86;
        pub mod analyzex86;
        pub mod emulatex86;
    }
}
pub mod analysis
{
    pub mod analyze;
    pub mod data_analyzer;
    pub mod signature_analysis;
    pub mod formats
    {
        #[macro_use]
        pub mod pe;
        pub mod peloader;
        pub mod macholoader;
        pub mod macho;

    }
}
