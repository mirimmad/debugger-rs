// A toy debugger for x86-64 linux.

use std::ffi::CString;
mod debugger;
use debugger::Debugger;

fn main() -> anyhow::Result<()> {
    // collect the args
    let args = std::env::args().collect::<Vec<String>>();
    if args.len() < 2 {
        eprintln!("Usage: {} <program name>", args[0]);
        std::process::exit(1);
    }

    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Parent { child, .. }) => {
            println!("Started debugger");
            let debugger = Debugger::new(&args[1], child);
            debugger.run()?;
        }
        Ok(nix::unistd::ForkResult::Child) => {
            println!("Child process ID: {}", nix::unistd::getpid());
            nix::sys::ptrace::traceme()?;
            let program_name = CString::new(args[1].as_bytes())?;
            let args = CString::new("")?;
            nix::unistd::execve(
                program_name.as_ref(),
                &[program_name.as_ref()],
                &[args.as_ref()],
            )?;
        }
        Err(e) => {
            eprintln!("Error forking: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
