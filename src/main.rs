// A toy debugger for x86-64 linux.

mod breakpoint;
mod debugger;
mod registers;
mod types;

use debugger::Debugger;
use std::ffi::CString;

fn main() -> anyhow::Result<()> {
    // collect the args
    let args = std::env::args().collect::<Vec<String>>();
    if args.len() < 2 {
        eprintln!("Usage: {} <program name>", args[0]);
        std::process::exit(-1);
    }

    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            println!("Started debugger");
            let mut debugger = Debugger::new(&args[1], child);
            debugger.run()?;
        }
        Ok(nix::unistd::ForkResult::Child) => {
            println!("Child process ID: {}", nix::unistd::getpid());
            nix::sys::ptrace::traceme()?;
            let program_name = CString::new(args[1].as_bytes())?;
            let args = CString::new("")?;
            // set process personality to no address space randomization
            unsafe { libc::personality(libc::ADDR_NO_RANDOMIZE as u64) };
            nix::unistd::execve(
                program_name.as_ref(),
                &[program_name.as_ref()],
                &[args.as_ref()],
            )?;
        }
        Err(e) => {
            eprintln!("Error forking: {}", e);
            std::process::exit(-1);
        }
    }

    Ok(())
}
