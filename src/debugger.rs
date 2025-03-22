use nix::sys::{ptrace, wait};
use nix::unistd::Pid;
use std::io::Write;

pub struct Debugger {
    prog_name: String,
    pid: Pid,
}

#[derive(Debug)]
enum Command {
    Quit,
    Continue,
    Unknown(String),
}

impl Debugger {
    pub fn new(prog_name: &str, pid: Pid) -> Self {
        Self {
            prog_name: prog_name.to_string(),
            pid,
        }
    }

    pub fn run(&self) -> anyhow::Result<()> {
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
            self.handle_input(&input)?;
        }
    }

    fn parse_command(&self, input: &str) -> Command {
        match input.trim() {
            cmd if "quit".starts_with(cmd) => Command::Quit,
            cmd if "continue".starts_with(cmd) => Command::Continue,
            cmd => Command::Unknown(cmd.to_owned()),
        }
    }
    
    fn handle_input(&self, input: &str) -> anyhow::Result<()> {
        let parts: Vec<&str> = input.trim().split_whitespace().collect();
        let command = parts[0];
        let command = self.parse_command(command);
        match command {
            Command::Quit => std::process::exit(0),
            Command::Continue => self.continue_execution()?,
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
}
