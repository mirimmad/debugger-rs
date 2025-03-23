use crate::breakpoint::Breakpoint;
use nix::sys::{ptrace, wait};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::io::Write;
pub struct Debugger {
    prog_name: String,
    pid: Pid,
    breakpoints: HashMap<u64, Breakpoint>,
}

#[derive(Debug)]
enum Command {
    Quit,
    Continue,
    SetBreakpoint(u64),
    Unknown(String),
}

impl Debugger {
    pub fn new(prog_name: &str, pid: Pid) -> Self {
        Self {
            prog_name: prog_name.to_string(),
            pid,
            breakpoints: HashMap::new(),
        }
    }

    pub fn run(&mut self) -> anyhow::Result<()> {
        let status = wait::waitpid(self.pid, None)?;
        println!("Program {} received signal {:?}", self.prog_name, status);

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
            Command::Unknown(cmd) => eprintln!("Unknown command: {}", cmd),
        }

        Ok(())
    }

    fn continue_execution(&self) -> anyhow::Result<()> {
        ptrace::cont(self.pid, None)?;

        let status = wait::waitpid(self.pid, None)?;
        eprintln!("received signal: {:?}", status);
        Ok(())
    }

    fn set_breakpoint(&mut self, addr: u64) -> anyhow::Result<()> {
        eprintln!("Setting breakpoint at address: {:x}", addr);
        let mut breakpoint = Breakpoint::new(self.pid, addr);
        breakpoint.enable()?;
        self.breakpoints.insert(addr, breakpoint);
        Ok(())
    }
}
