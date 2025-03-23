// source for representing a breakpoint
use nix::sys::ptrace;
use nix::unistd::Pid;
use std::ffi::c_void;

pub struct Breakpoint {
    pid: Pid,
    addr: u64,
    enabled: bool,
    saved_data: i64,
}

impl Breakpoint {
    pub fn new(pid: Pid, addr: u64) -> Self {
        Self {
            pid,
            addr,
            enabled: false,
            saved_data: 0,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn get_address(&self) -> u64 {
        self.addr
    }

    pub fn enable(&mut self) -> anyhow::Result<()> {
        let data = ptrace::read(self.pid, self.addr as *mut c_void)?;
        let saved_data = data & 0xff;
        let int3_encode = 0xcc;
        let data_with_int3 = (data & !0xff) | int3_encode;
        unsafe {
            ptrace::write(
                self.pid,
                self.addr as *mut c_void,
                data_with_int3 as *mut c_void,
            )?;
        };
        self.saved_data = saved_data;
        self.enabled = true;

        Ok(())
    }

    pub fn disable(&mut self) -> anyhow::Result<()> {
        if !self.is_enabled() {
            anyhow::bail!("Breakpoint is not enabled")
        }

        let data = ptrace::read(self.pid, self.addr as *mut c_void)?;
        let restored_data = (data & !0xff) | self.saved_data;
        unsafe {
            ptrace::write(
                self.pid,
                self.addr as *mut c_void,
                restored_data as *mut c_void,
            )?;
        };
        self.enabled = false;

        Ok(())
    }
}
