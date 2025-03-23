// x86-64 registers ordered as per libc::user_regs_struct
#[derive(Debug)]
pub enum Register {
    R15,
    R14,
    R13,
    R12,
    Rbp,
    Rbx,
    R11,
    R10,
    R9,
    R8,
    Rax,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    OrigRax,
    Rip,
    Cs,
    Eflags,
    Rsp,
    Ss,
    FsBase,
    GsBase,
    Ds,
    Es,
    Fs,
    Gs,
}

// array of resgister names
pub const REGISTER_NAMES: [&str; 27] = [
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi",
    "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs",
    "gs",
];

impl Register {
    pub fn from_regs(&self, regs: &libc::user_regs_struct) -> u64 {
        match self {
            Self::R15 => regs.r15,
            Self::R14 => regs.r14,
            Self::R13 => regs.r13,
            Self::R12 => regs.r12,
            Self::Rbp => regs.rbp,
            Self::Rbx => regs.rbx,
            Self::R11 => regs.r11,
            Self::R10 => regs.r10,
            Self::R9 => regs.r9,
            Self::R8 => regs.r8,
            Self::Rax => regs.rax,
            Self::Rcx => regs.rcx,
            Self::Rdx => regs.rdx,
            Self::Rsi => regs.rsi,
            Self::Rdi => regs.rdi,
            Self::OrigRax => regs.orig_rax,
            Self::Rip => regs.rip,
            Self::Cs => regs.cs,
            Self::Eflags => regs.eflags,
            Self::Rsp => regs.rsp,
            Self::Ss => regs.ss,
            Self::FsBase => regs.fs_base,
            Self::GsBase => regs.gs_base,
            Self::Ds => regs.ds,
            Self::Es => regs.es,
            Self::Fs => regs.fs,
            Self::Gs => regs.gs,
        }
    }

    pub fn to_regs(&self, value: u64, regset: &mut libc::user_regs_struct) {
        match self {
            Self::R15 => regset.r15 = value,
            Self::R14 => regset.r14 = value,
            Self::R13 => regset.r13 = value,
            Self::R12 => regset.r12 = value,
            Self::Rbp => regset.rbp = value,
            Self::Rbx => regset.rbx = value,
            Self::R11 => regset.r11 = value,
            Self::R10 => regset.r10 = value,
            Self::R9 => regset.r9 = value,
            Self::R8 => regset.r8 = value,
            Self::Rax => regset.rax = value,
            Self::Rcx => regset.rcx = value,
            Self::Rdx => regset.rdx = value,
            Self::Rsi => regset.rsi = value,
            Self::Rdi => regset.rdi = value,
            Self::OrigRax => regset.orig_rax = value,
            Self::Rip => regset.rip = value,
            Self::Cs => regset.cs = value,
            Self::Eflags => regset.eflags = value,
            Self::Rsp => regset.rsp = value,
            Self::Ss => regset.ss = value,
            Self::FsBase => regset.fs_base = value,
            Self::GsBase => regset.gs_base = value,
            Self::Ds => regset.ds = value,
            Self::Es => regset.es = value,
            Self::Fs => regset.fs = value,
            Self::Gs => regset.gs = value,
        }
    }

    pub fn get_reg_by_name(name: &str) -> Option<Self> {
        match name {
            "r15" => Some(Self::R15),
            "r14" => Some(Self::R14),
            "r13" => Some(Self::R13),
            "r12" => Some(Self::R12),
            "rbp" => Some(Self::Rbp),
            "rbx" => Some(Self::Rbx),
            "r11" => Some(Self::R11),
            "r10" => Some(Self::R10),
            "r9" => Some(Self::R9),
            "r8" => Some(Self::R8),
            "rax" => Some(Self::Rax),
            "rcx" => Some(Self::Rcx),
            "rdx" => Some(Self::Rdx),
            "rsi" => Some(Self::Rsi),
            "rdi" => Some(Self::Rdi),
            "orig_rax" => Some(Self::OrigRax),
            "rip" => Some(Self::Rip),
            "cs" => Some(Self::Cs),
            "eflags" => Some(Self::Eflags),
            "rsp" => Some(Self::Rsp),
            "ss" => Some(Self::Ss),
            "fs_base" => Some(Self::FsBase),
            "gs_base" => Some(Self::GsBase),
            "ds" => Some(Self::Ds),
            "es" => Some(Self::Es),
            "fs" => Some(Self::Fs),
            "gs" => Some(Self::Gs),
            _ => None,
        }
    }
}
