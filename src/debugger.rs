use crate::breakpoint::Breakpoint;
use crate::registers::{Register, REGISTER_NAMES};
use anyhow::Context;
use lazy_static::lazy_static;
use nix::sys::{ptrace, wait};
use nix::unistd::Pid;
use object::{Object, ObjectSection, ObjectSymbol};
use std::borrow::{self};
use std::collections::HashMap;
use std::ffi::c_void;
use std::io::{BufRead, Write};
use std::path::PathBuf;

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
    load_address: u64,
}

#[derive(Debug)]
enum Command {
    Quit,
    Continue,
    SetBreakpoint(String),
    RegisterDump,
    ReadRegister(Register),
    WriteRegister(Register, u64),
    ReadMemory(u64),
    SingleStepInstruction,
    StepIn,
    StepOut,
    StepOver,
    InfoBreakpoints,
    Symbol(String),
    Backtrace,
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
            load_address: 0,
        }
    }

    pub fn run(&mut self) -> anyhow::Result<()> {
        self.wait_for_signal()?;
        //println!("Program {} received signal {:?}", self.prog_name, status);
        self.initialise_load_address()?;
        //println!("Function: {}", self.get_function_form_pc(0x40113f)?);
        //let line_address = self.get_line_entry_form_pc(0x401126)?;
        //println!("Line: {:?}", line_address);
        //self.print_source_line(&line_address)?;
        //println!("Line entries: {:?}", self.get_all_line_entries(0x401126)?);
        // a loop for reading user input
        // break when user input "q"
        // self.set_break_point_line("step.c", 30)?;
        //println!("Symbol: {:?}", self.lookup_symbol("main")?);

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
                    let addr = parts.get(1).context("No subcommand provided")?;
                    Ok(Command::SetBreakpoint(addr.to_string()))
                }
                cmd if "register".starts_with(cmd) => {
                    if let Some(subcmd) = parts.get(1) {
                        if *subcmd == "dump" {
                            Ok(Command::RegisterDump)
                        } else if *subcmd == "read" {
                            let reg = parts.get(2).context("No register provided")?;
                            let reg = Register::get_reg_by_name(reg).context("Invalid register")?;
                            Ok(Command::ReadRegister(reg))
                        } else if *subcmd == "write" {
                            let reg = parts.get(2).context("No register provided")?;
                            let value = parts.get(3).context("No value provided")?;
                            let reg = Register::get_reg_by_name(reg).context("Invalid register")?;
                            let value =
                                u64::from_str_radix(&value[2..], 16).context("Invalid value")?;
                            Ok(Command::WriteRegister(reg, value))
                        } else {
                            anyhow::bail!("Unknown subcommand: {} {}", cmd, subcmd);
                        }
                    } else {
                        anyhow::bail!("No subcommand provided");
                    }
                }
                cmd if "info".starts_with(cmd) => {
                    if let Some(subcmd) = parts.get(1) {
                        if "breakpoints".starts_with(subcmd) {
                            Ok(Command::InfoBreakpoints)
                        } else {
                            anyhow::bail!("Unknown subcommand: {} {}", cmd, subcmd);
                        }
                    } else {
                        anyhow::bail!("No subcommand provided");
                    }
                }
                cmd if cmd == "read" => {
                    let addr = parts.get(1).context("No address provided")?;
                    let addr = u64::from_str_radix(&addr[2..], 16).context("Invalid address")?;
                    Ok(Command::ReadMemory(addr))
                }

                cmd if "step".starts_with(cmd) => Ok(Command::StepIn),
                cmd if "next".starts_with(cmd) => Ok(Command::StepOver),
                cmd if "finish".starts_with(cmd) => Ok(Command::StepOut),
                cmd if "stepi".starts_with(cmd) => Ok(Command::SingleStepInstruction),
                cmd if "symbol".starts_with(cmd) => {
                    let symbol_name = parts.get(1).context("No symbol name provided")?;
                    Ok(Command::Symbol(symbol_name.to_string()))
                }
                cmd if "backtrace".starts_with(cmd) => Ok(Command::Backtrace),
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
            Command::SetBreakpoint(cmd) => {
                self.set_breakpoint_cmd(cmd)?;
            }
            Command::RegisterDump => self.dump_registers()?,
            Command::ReadRegister(reg) => {
                println!("{:?}: 0x{:x}", reg, self.get_register_value(&reg)?);
            }
            Command::WriteRegister(reg, value) => {
                self.set_register_value(reg, value)?;
            }
            Command::ReadMemory(addr) => {
                println!("0x{:x}: 0x{:x}", addr, self.read_memory(addr)?);
            }
            Command::InfoBreakpoints => {
                for (addr, breakpoint) in &self.breakpoints {
                    println!("0x{:x}: {:?}", addr, breakpoint);
                }
            }
            Command::SingleStepInstruction => {
                self.single_step_instrution_over_breakpoint()?;
                let line_entry = self.get_line_entry_form_pc(self.get_pc()?)?;
                self.print_source_line(&line_entry)?;
            }
            Command::StepIn => self.step_in()?,
            Command::StepOut => self.step_out()?,
            Command::StepOver => self.step_over()?,
            Command::Symbol(symbol_name) => {
                let symbol = self.lookup_symbol(&symbol_name)?;
                println!("found '{}' at {:x}", symbol.name, symbol.address);
            }
            Command::Backtrace => self.print_backtrace()?,
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

    fn set_breakpoint_cmd(&mut self, cmd: String) -> anyhow::Result<()> {
        //let cmd = &cmd;
        if cmd.starts_with("0x") {
            let addr = &cmd[2..];
            //skip first two chars
            let addr = u64::from_str_radix(addr, 16).context("Invalid address")?;
            self.set_breakpoint(addr)?;
        } else if cmd.contains(":") {
            let parts: Vec<&str> = cmd.split(':').collect();
            let file = parts[0];
            let line = parts[1];
            self.set_break_point_line(file, line.parse::<u64>()?)?;
        } else {
            self.set_break_point_function(&cmd)?;
        }
        Ok(())
    }

    fn remove_breakpoint(&mut self, addr: u64) -> anyhow::Result<()> {
        if let Some(breakpoint) = self.breakpoints.get_mut(&addr) {
            breakpoint.disable()?;
            self.breakpoints.remove(&addr);
        }
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

    fn get_offset_pc(&self) -> anyhow::Result<u64> {
        Ok(self.offset_load_address(self.get_pc()?))
    }

    fn set_pc(&mut self, pc: u64) -> anyhow::Result<()> {
        self.set_register_value(Register::Rip, pc)
    }

    fn step_over_breakpoint(&mut self) -> anyhow::Result<()> {
        //let possible_breakpoint = self.get_pc()? - 1;
        let possible_breakpoint = self.get_pc()?;
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

    fn wait_for_signal(&mut self) -> anyhow::Result<()> {
        let status = wait::waitpid(self.pid, None)?;
        let siginfo = self.get_sig_info()?;
        match siginfo.si_signo {
            libc::SIGTRAP => self.handle_sigtrap(siginfo)?,
            libc::SIGSEGV => println!("Segmentation fault {}", siginfo.si_code),
            _ => eprintln!("received signal: {:?}", status),
        }
        Ok(())
    }

    fn handle_sigtrap(&mut self, siginfo: libc::siginfo_t) -> anyhow::Result<()> {
        match siginfo.si_code {
            libc::SI_KERNEL | libc::TRAP_BRKPT => {
                self.set_pc(self.get_pc()? - 1)?;
                println!("Breakpoint hit at {:x}", self.get_pc()?);
                let offset_pc = self.offset_load_address(self.get_pc()?);
                let line_entry = self.get_line_entry_form_pc(offset_pc)?;
                self.print_source_line(&line_entry)?;
                Ok(())
            }
            libc::TRAP_TRACE => Ok(()),
            _ => {
                println!("Unknown signal code: {}", siginfo.si_code);
                Ok(())
            }
        }
    }

    fn single_step_instruction(&mut self) -> anyhow::Result<()> {
        ptrace::step(self.pid, None)?;
        self.wait_for_signal()?;
        Ok(())
    }

    fn single_step_instrution_over_breakpoint(&mut self) -> anyhow::Result<()> {
        if self.breakpoints.contains_key(&self.get_pc()?) {
            self.step_over_breakpoint()?;
        } else {
            self.single_step_instruction()?;
        }
        Ok(())
    }

    fn step_out(&mut self) -> anyhow::Result<()> {
        let frame_pointer = self.get_register_value(&Register::Rbp)?;
        let return_address = self.read_memory(frame_pointer + 8)? as u64;

        let mut should_remove_breakpoint = false;
        if !self.breakpoints.contains_key(&return_address) {
            self.set_breakpoint(return_address)?;
            should_remove_breakpoint = true;
        }

        self.continue_execution()?;
        if should_remove_breakpoint {
            self.remove_breakpoint(return_address)?;
        }

        Ok(())
    }

    fn step_in(&mut self) -> anyhow::Result<()> {
        let line = self.get_line_entry_form_pc(self.get_offset_pc()?)?;
        // println!("step_inLine: {:?}", line);
        while self.get_line_entry_form_pc(self.get_offset_pc()?)?.line == line.line {
            //  println!("Stepping in");
            self.single_step_instrution_over_breakpoint()?;
        }
        let line = self.get_line_entry_form_pc(self.get_offset_pc()?)?;
        self.print_source_line(&line)?;
        Ok(())
    }

    fn step_over(&mut self) -> anyhow::Result<()> {
        let func = self.get_function_form_pc(self.get_offset_pc()?)?;
        let func_entry = func.low_pc;
        let func_end = func.high_pc;
        let start_line = self.get_line_entry_form_pc(func_entry)?;
        let line_entries = self.get_all_line_entries(func_entry)?;
        //println!("Line entries: {:?}", line_entries);

        let mut to_delete = vec![];
        for line_entry in line_entries {
            if line_entry.address < func_end {
                let load_address = self.offset_dwarf_address(line_entry.address);
                // println!("load_address: {:x}", load_address);
                if !line_entry.address == start_line.address
                    && !self.breakpoints.contains_key(&load_address)
                {
                    self.set_breakpoint(load_address)?;
                    to_delete.push(load_address);
                }
            }
        }

        let frame_pointer = self.get_register_value(&Register::Rbp)?;
        let return_address = self.read_memory(frame_pointer + 8)? as u64;
        /*  let rsp = self.get_register_value(&Register::Rsp)?;
        let rbp = self.get_register_value(&Register::Rbp)?;
        let rip = self.get_register_value(&Register::Rip)?;

        println!("Current registers:");
        println!("  RIP (instruction pointer): 0x{:x}", rip);
        println!("  RSP (stack pointer): 0x{:x}", rsp);
        println!("  RBP (base pointer): 0x{:x}", rbp); */

        // Dump stack memory around RBP
        /*  println!("\nStack memory around RBP:");
        for offset in -32i64..48i64 {
            let addr = (rbp as i64 + offset) as u64;
            let value = self.read_memory(addr)?;

            // Mark special addresses
            let marker = if offset == 0 {
                " <- RBP"
            } else if offset == 8 {
                " <- Return address?"
            } else if addr == rsp {
                " <- RSP"
            } else {
                ""
            };

            println!("  0x{:x} (RBP{:+3}): 0x{:x}{}", addr, offset, value, marker);

            // Try to get symbol information for values that look like code addresses
            if value >= self.load_address as i64 && value < 0x7fffffffffff {
                // Check if this address is in our program's code section
                if let Ok(function_name) = self.get_function_form_pc(value as u64) {
                    println!("    ^ Points to function: {}", function_name.name);
                }
            }
        } */

        if !self.breakpoints.contains_key(&return_address) {
            self.set_breakpoint(return_address)?;
            to_delete.push(return_address);
        }

        self.continue_execution()?;
        for addr in to_delete {
            self.remove_breakpoint(addr)?;
        }

        Ok(())
    }
    // get info about a function from PC
    fn get_function_form_pc(&self, pc: u64) -> anyhow::Result<crate::types::Function> {
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
                            //println!("attr value: {:?} Low PC: {:x?}", attr.value(), low_pc);
                        }
                        if attr.name() == gimli::constants::DW_AT_high_pc {
                            //high_pc = attr.value().sdata_value().unwrap_or(-1) as i64;
                            high_pc = Some(attr_to_number!(attr.value())?);
                            //println!("High PC: {:?}", high_pc);
                        }
                        if let Ok(s) = unit.attr_string(attr.value()) {
                            name = Some(s.to_string()?);
                        }
                    }

                    if let (Some(low_pc), Some(high_pc), Some(name)) = (low_pc, high_pc, name) {
                        // print all values
                        /* println!(
                            "PC: {:?}, Low PC: {:?}, High PC: {:?}, Name: {:?}",
                            pc,
                            low_pc,
                            low_pc + high_pc,
                            name
                        ); */
                        if pc >= low_pc && pc < (low_pc + high_pc) {
                            return Ok(crate::types::Function {
                                name: name.to_string(),
                                low_pc,
                                high_pc,
                            });
                        }
                    }
                }
            }
        }
        anyhow::bail!("No function found for PC: {:x}", pc);
    }

    fn get_line_entry_form_pc(&self, pc: u64) -> anyhow::Result<crate::types::LineAddress> {
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

        while let Some(header) = iter.next()? {
            let unit = dwarf.unit(header)?;

            let unit = unit.unit_ref(&dwarf);

            let mut entries = unit.entries();
            let mut low_pc = 0;
            let mut high_pc = 0;
            while let Some((_, entry)) = entries.next_dfs()? {
                if entry.tag() == gimli::constants::DW_TAG_compile_unit {
                    let mut attrs = entry.attrs();
                    while let Some(attr) = attrs.next()? {
                        if attr.name() == gimli::constants::DW_AT_low_pc {
                            low_pc = attr_to_number!(attr.value())?;
                        }
                        if attr.name() == gimli::constants::DW_AT_high_pc {
                            high_pc = attr_to_number!(attr.value())?;
                        }
                    }
                    break;
                }
            }
            let mut last_line_entry;
            //println!("low_pc: {:x} high_pc: {:x}", low_pc, high_pc);
            if low_pc != 0 && high_pc != 0 && pc >= low_pc && pc < (high_pc + low_pc) {
                if let Some(line_table) = unit.line_program.clone() {
                    let mut rows = line_table.rows();
                    while let Some((header, row)) = rows.next_row()? {
                        let line = row.line().ok_or(anyhow::anyhow!("No line found"))?;
                        let column = match row.column() {
                            gimli::ColumnType::Column(column) => column.get(),
                            gimli::ColumnType::LeftEdge => 0,
                        };
                        let addr = row.address();

                        let file = row.file(header).ok_or(anyhow::anyhow!("No file found"))?;
                        let dir = file
                            .directory(header)
                            .ok_or(anyhow::anyhow!("No directory found"))?;
                        let file_str = unit.attr_string(file.path_name())?.to_string()?;
                        let dir_str = unit.attr_string(dir)?.to_string()?;
                        let path = PathBuf::from(dir_str).join(file_str);
                        let line_address = crate::types::LineAddress {
                            line: line.get(),
                            column,
                            address: addr,
                            filepath: path,
                        };
                        last_line_entry = line_address.clone();
                        if addr == pc {
                            //println!("line_address: {:x?}", line_address);
                            return Ok(line_address);
                        }

                        if addr > pc {
                            // println!("last_line_entry: {:x?}", last_line_entry);
                            return Ok(last_line_entry);
                        }
                    }
                }
            } else {
                anyhow::bail!("out of range PC: {:x}", pc);
            }
        }

        anyhow::bail!("No line entry found for PC: {:x}", pc);
    }

    fn set_break_point_function(&mut self, name: &str) -> anyhow::Result<()> {
        let function = self.get_function_form_pc(self.get_pc()?)?;
        if function.name == name {
            self.set_breakpoint(function.low_pc)?;
        }
        Ok(())
    }

    fn set_break_point_line(&mut self, file: &str, line_number: u64) -> anyhow::Result<()> {
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

        // Iterate through compilation units

        let mut iter = dwarf.units();
        while let Some(header) = iter.next()? {
            let unit = dwarf.unit(header)?;

            let unit = unit.unit_ref(&dwarf);

            let mut entries = unit.entries();

            while let Some((_, entry)) = entries.next_dfs()? {
                if entry.tag() == gimli::constants::DW_TAG_compile_unit {
                    let mut attrs = entry.attrs();
                    while let Some(attr) = attrs.next()? {
                        if attr.name() == gimli::constants::DW_AT_name {
                            if let Ok(s) = unit.attr_string(attr.value()) {
                                let name = Some(s.to_string()?);
                                if name == Some(file) {
                                    if let Some(line_table) = unit.line_program.clone() {
                                        let mut rows = line_table.rows();
                                        while let Some((_, row)) = rows.next_row()? {
                                            let line = row
                                                .line()
                                                .ok_or(anyhow::anyhow!("No line found"))?;
                                            let line = line.get();
                                            if line == line_number && row.is_stmt() {
                                                self.set_breakpoint(
                                                    self.offset_dwarf_address(row.address()),
                                                )?;
                                                return Ok(());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        anyhow::bail!("Could not find line {} in file {}", line_number, file)
    }

    fn get_all_line_entries(&self, addr: u64) -> anyhow::Result<Vec<crate::types::LineAddress>> {
        // if the CU contains the address, return all line entries
        // otherwise, return an empty vector
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
        while let Some(header) = iter.next()? {
            let unit = dwarf.unit(header)?;
            let unit = unit.unit_ref(&dwarf);

            let mut rows = unit.line_program.clone().unwrap().rows();
            let mut line_addresses = Vec::new();
            while let Some((header, row)) = rows.next_row()? {
                let line = row.line().ok_or(anyhow::anyhow!("No line found"))?;
                let column = match row.column() {
                    gimli::ColumnType::Column(column) => column.get(),
                    gimli::ColumnType::LeftEdge => 0,
                };
                let row_addr = row.address();
                // println!("Row addr: {:x} {:?} {}", row_addr, line, column);

                let file = row.file(header).ok_or(anyhow::anyhow!("No file found"))?;
                let dir = file
                    .directory(header)
                    .ok_or(anyhow::anyhow!("No directory found"))?;
                let file_str = unit.attr_string(file.path_name())?.to_string()?;
                let dir_str = unit.attr_string(dir)?.to_string()?;
                let path = PathBuf::from(dir_str).join(file_str);
                let line_address = crate::types::LineAddress {
                    line: line.get(),
                    column,
                    address: row_addr,
                    filepath: path,
                };
                line_addresses.push(line_address);
            }
            let line_addresses = line_addresses
                .into_iter()
                .filter(|line_address| line_address.address >= addr)
                .collect::<Vec<_>>();
            return Ok(line_addresses);
        }
        Ok(Vec::new())
    }

    fn initialise_load_address(&mut self) -> anyhow::Result<()> {
        let kind = self.elf.kind();
        if kind == object::ObjectKind::Dynamic {
            let maps_file = std::fs::File::open(format!("/proc/{}/maps", self.pid))?;
            // read the first line of the file
            let reader = std::io::BufReader::new(maps_file);
            let Some(Ok(line)) = reader.lines().next() else {
                anyhow::bail!("Failed to read line from maps file");
            };
            let parts: Vec<&str> = line.split('-').collect();
            let start_addr = u64::from_str_radix(parts[0], 16)?;
            self.load_address = start_addr;
        }
        Ok(())
    }

    fn offset_load_address(&self, addr: u64) -> u64 {
        addr - self.load_address
    }

    fn offset_dwarf_address(&self, addr: u64) -> u64 {
        addr + self.load_address
    }

    fn print_source_line(&self, line_address: &crate::types::LineAddress) -> anyhow::Result<()> {
        let file = std::fs::File::open(line_address.filepath.clone())?;
        let reader = std::io::BufReader::new(file);
        let mut lines = reader.lines();
        let line = lines.nth(line_address.line as usize - 1).unwrap()?;
        println!("{} | {}", line_address.line, line);
        let space = " ".repeat(line_address.column as usize);
        println!("   {}{}", space, "^");
        Ok(())
    }

    fn lookup_symbol(&self, symbol_name: &str) -> anyhow::Result<crate::types::Symbol> {
        let syms = self.elf.symbols();
        for sym in syms {
            if let Ok(name) = sym.name() {
                if name == symbol_name {
                    return Ok(crate::types::Symbol {
                        name: name.to_string(),
                        address: sym.address(),
                    });
                }
            }
        }
        anyhow::bail!("Symbol not found: {}", symbol_name);
    }

    fn print_backtrace(&self) -> anyhow::Result<()> {
        let mut frame_number = 1;
        let mut print_frame = |func: &crate::types::Function| -> anyhow::Result<()> {
            println!("frame #{}: 0x{:x} {}", frame_number, func.low_pc, func.name);
            frame_number += 1;
            Ok(())
        };

        let mut current_function =
            self.get_function_form_pc(self.offset_load_address(self.get_pc()?))?;
        print_frame(&current_function)?;

        let mut frame_pointer = self.get_register_value(&Register::Rbp)?;
        let mut return_address = self.read_memory(frame_pointer + 8)? as u64;

        while current_function.name != "main" {
            current_function =
                self.get_function_form_pc(self.offset_load_address(return_address))?;
            print_frame(&current_function)?;
            frame_pointer = self.read_memory(frame_pointer)? as u64;
            return_address = self.read_memory(frame_pointer + 8)? as u64;
        }

        Ok(())
    }

    fn get_sig_info(&self) -> anyhow::Result<libc::siginfo_t> {
        let siginfo = nix::sys::ptrace::getsiginfo(self.pid)?;
        Ok(siginfo)
    }
}
