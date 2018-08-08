![alt text](xori.png "Xori Logo")
# Xori - Custom disassembly framework

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)


Xori is an automation-ready disassembly and static analysis library that consumes shellcode or PE binaries and provides triage analysis data.

## Architectures:
* i386
* x86-64

## File Formats
* PE, PE+
* Plain shellcode

## Current Features
* Outputs json of the 1) Disassembly, 2) Functions, and 3) Imports.
* Manages Image and Stack memory.
* 2 modes:
  * Light Emulation - meant to enumerate all paths (Registers, Stack, Some Instructions).
  * Full Emulation - only follows the code’s path (Slow performance).
* Simulated TEB & PEB structures.
* Evaluates functions based on DLL exports.
* Displays strings based on referenced memory locations.
* Uses FLIRT style signatures (Fast Library Identification and Recognition Technology).
* Allows you to use your own exports for simulating the PEB.
* Will detect padding after a non-returning call.
* Will try to identify function references from offsets.

What it doesn't do yet:
* The engine is interactive.
* Does not dump strings.
* Does not process non-executable sections.
* TEB and PEB are not enabled for non-pe files.
* Only some x86 instructions are emulated, not all.
* Patching and assembling.
* No plugins or scripting.


## [Documentation](doc/xori/)

## Requirements
rustc 1.27.0

### Install rust for OSX & Linux Distros

```
curl https://sh.rustup.rs -sSf | sh
```

### Install rust for Windows

https://www.rust-lang.org/en-US/other-installers.html

Select: 
* x86_64-pc-windows-gnu or 
* x86_64-pc-windows-msvc (Visual Studio Build Tools Required)

# Installation

## 1. Build Xori

This command will also create other binaries such as pesymbols ans peinfo.

```
git clone https://github.com/endgameinc/xori.git
cd xori
cargo build --release
```

## 2. Create xori.json config file

```
cp xori.json.example xori.json
[edit if desired]
```

## 3. (Optional) Build the symbols files

If you want to create your own symbol files you need to set the dll folders to where you stored your windows dlls. 

```
"function_symbol32": "./src/analysis/symbols/generated_user_syswow64.json",
"function_symbol64": "./src/analysis/symbols/generated_user_system32.json",
"symbol_server": {
	"dll_folder32": "./dlls/32bit",
	"dll_folder64": "./dlls/64bit"
```

Run pesymbols to overwrite the function_symbol json

```
 ./target/release/pesymbols
```

# Run

```
./target/release/xori -f test.exe
```

## Run all tests

```
cargo test
```

# Browser GUI

Chrome | Firefox | Safari | IE | Opera
--- | --- | --- | --- | --- |
Latest ✔ | Latest ✔ | Latest ✔ | x | Latest ✔ |

## Requirements

nodejs
yarn (optional for UI dev)


## Build

```
cd gui
npm install
```

## Run

In one terminal
```
cd gui
node src/server.js
```
In another terminal
```
cd gui
npm start
```

It will open your default browser to http://localhost:3000/.
The backend API is listening on localhost:5000.
