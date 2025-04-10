use crate::breakpoint::Breakpoint;
use crate::registers::{Register, REGISTER_NAMES};
use anyhow::Context;
use lazy_static::lazy_static;
use nix::sys::{ptrace, wait};
use nix::unistd::Pid;
use object::{Object, ObjectSection};
use std::borrow::{self};
use std::collections::HashMap;
use std::ffi::c_void;
use std::io::Write;

macro_rules! attr_to_number {
    ($attr_value:expr) => {{
        match $attr_value {
            gimli::AttributeValue::Addr(addr) => Ok(addr),
            gimli::AttributeValue::Udata(data) => Ok(data),
            //gimli::AttributeValue::Sdata(data) => Ok(data),

            _ => anyhow::bail!("Attribute value is not a number: {:?}", $attr_value),
        }
    } as anyhow::Result<u64>};
}

lazy_static! {
    static ref PROG_NAME: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
    static ref MMAP: memmap2::Mmap = {
        let prog_name = PROG_NAME.lock().unwrap();
        let file = std::fs::File::open(&*prog_name).unwrap();
        let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };
        mmap
    };
}

pub struct Debugger<'a> {
    prog_name: String,
    pid: Pid,
    breakpoints: HashMap<u64, Breakpoint>,
    elf: object::File<'a>,
    endianess: gimli::RunTimeEndian,
}

#[derive(Debug)]
enum Command {
    Quit,
    Continue,
    SetBreakpoint(u64),
    RegisterDump,
    ReadRegister(Register),
    WriteRegister(Register, u64),
    Unknown(String),
}

impl<'a> Debugger<'a> {
    pub fn new(prog_name: &str, pid: Pid) -> Self {
        PROG_NAME.lock().unwrap().push_str(prog_name);
        let elf = object::File::parse(&**MMAP).expect("Failed to parse object file");
        let endianess = if elf.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };
        Self {
            prog_name: prog_name.to_string(),
            pid,
            breakpoints: HashMap::new(),
            elf,
            endianess,
        }
    }

    pub fn run(&mut self) -> anyhow::Result<()> {
        let status = wait::waitpid(self.pid, None)?;
        println!("Program {} received signal {:?}", self.prog_name, status);
        println!("Function: {}", self.get_function_form_pc(0x40113f)?);
        // a loop for reading user input
        // break when user input "q"

        loop {
            let mut input = String::new();
            print!("> ");
            std::io::stdout().flush()?;
            std::io::stdin().read_line(&mut input)?;
            if input.trim().is_empty() {
                continue;
            }
            if let Err(e) = self.handle_input(&input) {
                println!("Error: {}", e);
            }
        }
    }

    fn parse_command(&self, parts: Vec<&str>) -> anyhow::Result<Command> {
        if let Some(command) = parts.get(0) {
            match command.trim() {
                cmd if "quit".starts_with(cmd) => Ok(Command::Quit),
                cmd if "continue".starts_with(cmd) => Ok(Command::Continue),
                cmd if "breakpoint".starts_with(cmd) => {
                    let addr = parts.get(1).expect("No address provided");
                    // skip first two chars
                    let addr = &addr[2..];
                    let addr = u64::from_str_radix(addr, 16).expect("Invalid address");
                    Ok(Command::SetBreakpoint(addr))
                }
                cmd if "register".starts_with(cmd) => {
                    if let Some(subcmd) = parts.get(1) {
                        if *subcmd == "dump" {
                            Ok(Command::RegisterDump)
                        } else if *subcmd == "read" {
                            let reg = parts.get(2).expect("No register provided");
                            let reg = Register::get_reg_by_name(reg).context("Invalid register")?;
                            Ok(Command::ReadRegister(reg))
                        } else if *subcmd == "write" {
                            let reg = parts.get(2).expect("No register provided");
                            let value = parts.get(3).expect("No value provided");
                            let reg = Register::get_reg_by_name(reg).expect("Invalid register");
                            let value =
                                u64::from_str_radix(&value[2..], 16).expect("Invalid value");
                            Ok(Command::WriteRegister(reg, value))
                        } else {
                            anyhow::bail!("Unknown subcommand: {} {}", cmd, subcmd);
                        }
                    } else {
                        anyhow::bail!("No subcommand provided");
                    }
                }
                cmd => Ok(Command::Unknown(cmd.to_owned())),
            }
        } else {
            anyhow::bail!("No command provided");
        }
    }

    fn handle_input(&mut self, input: &str) -> anyhow::Result<()> {
        let parts: Vec<&str> = input.trim().split_whitespace().collect();
        let command = self.parse_command(parts)?;
        match command {
            Command::Quit => std::process::exit(0),
            Command::Continue => self.continue_execution()?,
            Command::SetBreakpoint(addr) => {
                self.set_breakpoint(addr)?;
            }
            Command::RegisterDump => self.dump_registers()?,
            Command::ReadRegister(reg) => {
                println!("{:?}: 0x{:x}", reg, self.get_register_value(&reg)?);
            }
            Command::WriteRegister(reg, value) => {
                self.set_register_value(reg, value)?;
            }
            Command::Unknown(cmd) => eprintln!("Unknown command: {}", cmd),
        }

        Ok(())
    }

    fn continue_execution(&mut self) -> anyhow::Result<()> {
        self.step_over_breakpoint()?;
        ptrace::cont(self.pid, None)?;
        self.wait_for_signal()?;
        Ok(())
    }

    fn set_breakpoint(&mut self, addr: u64) -> anyhow::Result<()> {
        eprintln!("Setting breakpoint at address: {:x}", addr);
        let mut breakpoint = Breakpoint::new(self.pid, addr);
        breakpoint.enable()?;
        self.breakpoints.insert(addr, breakpoint);
        Ok(())
    }

    fn get_register_value(&self, reg: &Register) -> anyhow::Result<u64> {
        let regs = ptrace::getregs(self.pid)?;
        Ok(reg.from_regs(&regs))
    }

    fn set_register_value(&self, reg: Register, value: u64) -> anyhow::Result<()> {
        let mut regs = ptrace::getregs(self.pid)?;
        reg.to_regs(value, &mut regs);
        ptrace::setregs(self.pid, regs)?;
        Ok(())
    }

    fn dump_registers(&self) -> anyhow::Result<()> {
        // dump all registers
        let regs = ptrace::getregs(self.pid)?;
        for reg in REGISTER_NAMES {
            let reg = Register::get_reg_by_name(reg).unwrap();
            let value = reg.from_regs(&regs);
            println!("{:?}: 0x{:x}", reg, value);
        }

        Ok(())
    }

    fn read_memory(&self, addr: u64) -> anyhow::Result<i64> {
        Ok(ptrace::read(self.pid, addr as *mut c_void)?)
    }

    fn write_memory(&self, addr: u64, value: i64) -> anyhow::Result<()> {
        unsafe {
            ptrace::write(self.pid, addr as *mut c_void, value as *mut c_void)?;
        }
        Ok(())
    }

    fn get_pc(&self) -> anyhow::Result<u64> {
        let regs = ptrace::getregs(self.pid)?;
        Ok(regs.rip)
    }

    fn set_pc(&mut self, pc: u64) -> anyhow::Result<()> {
        self.set_register_value(Register::Rip, pc)
    }

    fn step_over_breakpoint(&mut self) -> anyhow::Result<()> {
        let possible_breakpoint = self.get_pc()? - 1;

        let should_step = self
            .breakpoints
            .get(&possible_breakpoint)
            .map(|b| b.is_enabled())
            .unwrap_or(false);

        if should_step {
            self.set_pc(possible_breakpoint)?;
            if let Some(breakpoint) = self.breakpoints.get_mut(&possible_breakpoint) {
                breakpoint.disable()?;
            }

            ptrace::step(self.pid, None)?;
            self.wait_for_signal()?;

            if let Some(breakpoint) = self.breakpoints.get_mut(&possible_breakpoint) {
                breakpoint.enable()?;
            }
        }

        Ok(())
    }

    fn wait_for_signal(&self) -> anyhow::Result<()> {
        let status = wait::waitpid(self.pid, None)?;
        eprintln!("received signal: {:?}", status);
        Ok(())
    }

    // get info about a function from PC
    fn get_function_form_pc(&self, pc: u64) -> anyhow::Result<String> {
        let borrow_section =
            |section| gimli::EndianSlice::new(borrow::Cow::as_ref(section), self.endianess);
        let load_section = |id: gimli::SectionId| -> anyhow::Result<borrow::Cow<[u8]>> {
            Ok(match self.elf.section_by_name(id.name()) {
                Some(section) => section.uncompressed_data()?,
                None => borrow::Cow::Borrowed(&[]),
            })
        };
        let dwarf_sections = gimli::DwarfSections::load(&load_section)?;
        let dwarf = dwarf_sections.borrow(borrow_section);
        let mut iter = dwarf.units();

        let mut low_pc = None;
        let mut high_pc = None;
        let mut name = None;

        while let Some(header) = iter.next()? {
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();
            let unit = unit.unit_ref(&dwarf);

            while let Some((_, entry)) = entries.next_dfs()? {
                if entry.tag() == gimli::constants::DW_TAG_subprogram {
                    let mut attrs = entry.attrs();

                    while let Some(attr) = attrs.next()? {
                        if attr.name() == gimli::constants::DW_AT_low_pc {
                            low_pc = Some(attr_to_number!(attr.value())?);
                            println!("attr value: {:?} Low PC: {:x?}", attr.value(), low_pc);
                        }
                        if attr.name() == gimli::constants::DW_AT_high_pc {
                            //high_pc = attr.value().sdata_value().unwrap_or(-1) as i64;
                            high_pc = Some(attr_to_number!(attr.value())?);
                            println!("High PC: {:?}", high_pc);
                        }
                        if let Ok(s) = unit.attr_string(attr.value()) {
                            name = Some(s.to_string()?);
                        }
                    }

                    if let (Some(low_pc), Some(high_pc), Some(name)) = (low_pc, high_pc, name) {
                        // print all values
                        println!(
                            "PC: {:?}, Low PC: {:?}, High PC: {:?}, Name: {:?}",
                            pc,
                            low_pc,
                            low_pc + high_pc,
                            name
                        );
                        if pc >= low_pc && pc < (low_pc + high_pc) {
                            return Ok(name.to_string());
                        }
                    }
                }
            }
        }
        anyhow::bail!("No function found for PC: {:x}", pc);
    }
}
