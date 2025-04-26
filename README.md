## debugger-rs


A simple toy debugger implementation in Rust This project demonstrates how to create a basic debugger that can control program execution, set breakpoints, inspect memory and registers, and analyze debug information.

## Features
- Process control (start, stop, continue)
- Breakpoint management
- Memory inspection
- Register access
- Source line information
- Function name resolution
- Backtrace generation

## Usage

```bash
cargo run /path/to/your/program
```
## available commands

The debugger supports command prefixes, so you can use shortened versions of commands. For example, 'b' instead of 'breakpoint', 'c' for 'continue', or 'i b' for 'info breakpoints'.

Full command list:
```bash
quit (q)
continue (c)
breakpoint (b) 0xABCD
breakpoint (b) func
breakpoint (b) file.c:1
register (r) dump
register (r) read rax
register (r) write rax 0x1234
info (i) breakpoints
read 0xABCD
step (s)
next (n)
finish (f)
stepi (si)
symbol (sym) NAME
backtrace (bt)
quit (q)
```