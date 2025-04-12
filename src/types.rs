use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct LineAddress {
    pub line: u64,
    pub column: u64,
    pub address: u64,
    pub filepath: PathBuf,
}
