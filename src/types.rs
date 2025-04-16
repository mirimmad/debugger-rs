use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct LineAddress {
    pub line: u64,
    pub column: u64,
    pub address: u64,
    pub filepath: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub low_pc: u64,
    pub high_pc: u64,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
}
