#![allow(dead_code)]
mod name;
mod process;
mod procfs;

use argh::FromArgs;
use std::error::Error;

#[derive(FromArgs, PartialEq, Debug)]
#[argh(description = "Top-level command")]
struct Args {
    #[argh(subcommand)]
    nested: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Autosym(AutosymArgs),
    Run(RunArgs),
    Dig(DigArgs),
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "dig")]
/// Shows information about an address in a memory's address space
struct DigArgs {
    #[argh(option)]
    /// the PID of the process whose memory space to examine
    pid: u32,
    #[argh(option)]
    /// the address to look for
    addr: u64,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "autosym")]
#[argh(description = "Given a PID, spit out GDB commands to load all .so files mapped in memory.")]
struct AutosymArgs {
    #[argh(positional)]
    pid: u32,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(description = "Load and run an ELF executable")]
#[argh(subcommand, name = "run")]
struct RunArgs {
    #[argh(positional)]
    exec_path: String,
}

fn main() {
    if let Err(e) = do_main() {
        eprintln!("Fatal error: {}", e);
    }
}

type AnyError = Box<dyn Error>;

fn do_main() -> Result<(), AnyError> {
    let args: Args = argh::from_env();
    match args.nested {
        SubCommand::Run(args) => cmd_run(args),
        SubCommand::Autosym(args) => cmd_autosym(args),
        SubCommand::Dig(args) => cmd_dig(args),
    }
}

use thiserror::*;

#[derive(Error, Debug)]
enum WithMappingsError {
    #[error("parsing failed: {0}")]
    Parse(String),
}

fn with_mappings<F, T>(pid: u32, f: F) -> Result<T, AnyError>
where
    F: Fn(&Vec<procfs::Mapping<'_>>) -> Result<T, Box<dyn Error>>,
{
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid))?;
    match procfs::mappings(&maps) {
        Ok((_, maps)) => f(&maps),
        Err(e) => Err(Box::new(WithMappingsError::Parse(format!("{:?}", e)))),
    }
}

fn cmd_autosym(args: AutosymArgs) -> Result<(), AnyError> {
    fn analyze(mapping: &procfs::Mapping) -> Result<(), AnyError> {
        if mapping.deleted {
            return Ok(());
        }

        let path = match mapping.source {
            procfs::Source::File(path) => path,
            _ => return Ok(()),
        };

        let contents = std::fs::read(path)?;
        let file = match delf::File::parse_or_print_error(&contents) {
            Some(x) => x,
            _ => return Ok(()),
        };

        let section = match file
            .section_headers
            .iter()
            .find(|sh| file.shstrtab_entry(sh.name) == b".text")
        {
            Some(section) => section,
            _ => return Ok(()),
        };

        let textaddress = mapping.addr_range.start - mapping.offset + section.offset;
        println!("add-symbol-file {:?} 0x{:?}", path, textaddress);

        Ok(())
    }

    with_mappings(args.pid, |mappings| {
        for mapping in mappings.iter().filter(|m| m.perms.x && m.source.is_file()) {
            analyze(mapping)?;
        }
        Ok(())
    })
}

struct Size(pub delf::Addr);

use std::fmt;
impl fmt::Debug for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const KIB: u64 = 1024;
        const MIB: u64 = 1024 * KIB;

        let x = (self.0).0;
        #[allow(overlapping_range_endpoints)]
        #[allow(clippy::clippy::match_overlapping_arm)]
        match x {
            0..=KIB => write!(f, "{} B", x),
            KIB..=MIB => write!(f, "{} KiB", x / KIB),
            _ => write!(f, "{} MiB", x / MIB),
        }
    }
}

fn cmd_dig(args: DigArgs) -> Result<(), Box<dyn Error>> {
    let addr = delf::Addr(args.addr);

    with_mappings(args.pid, |mappings| {
        if let Some(mapping) = mappings.iter().find(|m| m.addr_range.contains(&addr)) {
            println!("Mapped {:?} from {:?}", mapping.perms, mapping.source);
            println!(
                "(Map range: {:?}, {:?} total)",
                mapping.addr_range,
                Size(mapping.addr_range.end - mapping.addr_range.start)
            );

            let path = match mapping.source {
                procfs::Source::File(path) => path,
                _ => return Ok(()),
            };

            let contents = std::fs::read(path)?;
            let file = match delf::File::parse_or_print_error(&contents) {
                Some(x) => x,
                _ => return Ok(()),
            };

            let offset = addr + mapping.offset - mapping.addr_range.start;

            let segment = match file
                .program_headers
                .iter()
                .find(|ph| ph.file_range().contains(&offset))
            {
                Some(s) => s,
                None => return Ok(()),
            };

            let vaddr = offset + segment.vaddr - segment.offset;
            println!("Object virtual address: {:?}", vaddr);

            let section = match file
                .section_headers
                .iter()
                .find(|sh| sh.mem_range().contains(&vaddr))
            {
                Some(s) => s,
                None => return Ok(()),
            };

            let name = file.shstrtab_entry(section.name);
            let sect_offset = vaddr - section.addr;
            println!(
                "At section {:?} + {} (0x{:x})",
                String::from_utf8_lossy(name),
                sect_offset.0,
                sect_offset.0
            );

            match file.read_symtab_entries() {
                Ok(syms) => {
                    for sym in &syms {
                        let sym_range = sym.value..(sym.value + delf::Addr(sym.size));
                        if sym.value == vaddr || sym_range.contains(&vaddr) {
                            let sym_offset = vaddr - sym.value;
                            let sym_name = String::from_utf8_lossy(file.strtab_entry(sym.name));
                            println!(
                                "At symbol {:?} + {} (0x{:x})",
                                sym_name, sym_offset.0, sym_offset.0
                            );
                        }
                    }
                }
                Err(e) => println!("Could not read syms: {:?}", e),
            }
        }
        Ok(())
    })
}

fn cmd_run(args: RunArgs) -> Result<(), Box<dyn Error>> {
    let mut proc = process::Process::new();
    let exec_index = proc.load_object_and_dependencies(args.exec_path)?;
    proc.apply_relocations()?;
    proc.adjust_protections()?;

    let exec_obj = &proc.objects[exec_index];
    let entry_point = exec_obj.file.entry_point + exec_obj.base;
    unsafe { jmp(entry_point.as_ptr()) };

    Ok(())
}

unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}

// And this little helper function is new as well!
#[allow(unused)]
fn pause(reason: &str) -> Result<(), Box<dyn Error>> {
    println!("Press Enter to {}...", reason);
    {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
    }
    Ok(())
}

/**
 * Truncates a usize value to the left-adjacent (low) 4KiB boundary.
 */
fn align_lo(x: usize) -> usize {
    x & !0xFFF
}

#[allow(unused)]
fn ndisasm(code: &[u8], origin: delf::Addr) -> Result<(), Box<dyn Error>> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    let mut child = Command::new("ndisasm")
        .arg("-b")
        .arg("64")
        .arg("-o")
        .arg(format!("{}", origin.0))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child.stdin.as_mut().unwrap().write_all(code)?;
    let output = child.wait_with_output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}
