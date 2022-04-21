use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};
use std::{env, error::Error, fs};

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("usage: elf FILE");
    let input = fs::read(&input_path)?;
    let file = match delf::File::parse_or_print_error(&input[..]) {
        Some(f) => f,
        None => std::process::exit(1),
    };
    println!("{:#?}", file);

    println!("Disassembling {:?}...", input_path);
    let code_ph = file
        .program_headers
        .iter()
        .find(|ph| ph.mem_range().contains(&file.entry_point))
        .expect("segment with entry point not found");

    // ndisasm(&code_ph.data[..], file.entry_point)?;

    println!("Dynamic entries:");
    if let Some(ds) = file
        .program_headers
        .iter()
        .find(|ph| ph.r#type == delf::SegmentType::Dynamic)
    {
        if let delf::SegmentContents::Dynamic(ref table) = ds.contents {
            for entry in table {
                println!(" - {:?}", entry);
            }
        }
    }

    println!("Rela entries:");
    let rela_entries = file.read_rela_entries()?;
    // for e in &rela_entries {
    //     println!("{:#?}", e);
    //     if let Some(seg) = file.segment_at(e.offset) {
    //         println!("... for {:#?}", seg);
    //     }
    // }

    // picked by fair 4KiB-aligned dice roll
    let base = 0x400000_usize;
    println!("Mapping {:?} in memory...", input_path);
    let mut mappings = Vec::new();
    for ph in file
        .program_headers
        .iter()
        .filter(|ph| ph.r#type == delf::SegmentType::Load)
        // ignore zero-length segments
        .filter(|ph| ph.mem_range().end > ph.mem_range().start)
    {
        println!("Mapping segment @ {:?} with {:?}", ph.mem_range(), ph.flags);
        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();

        let start: usize = mem_range.start.0 as usize + base;
        let aligned_start: usize = align_lo(start);
        let padding = start - aligned_start;
        let len = len + padding;

        let addr: *mut u8 = unsafe { std::mem::transmute(aligned_start) };
        println!("Addr: {:p}, Padding: {:08x}", addr, padding);

        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;

        println!("Copying segment data...");
        unsafe {
            std::ptr::copy_nonoverlapping(ph.data.as_ptr(), addr.add(padding), len);
        }

        println!("Applying relocations (if any)...");
        for reloc in &rela_entries {
            if mem_range.contains(&reloc.offset) {
                unsafe {
                    use std::mem::transmute as trans;
                    let real_segment_start = addr.add(padding);

                    let specified_reloc_offset = reloc.offset;
                    let specified_segment_start = mem_range.start;
                    let offset_into_segment = specified_reloc_offset - specified_segment_start;

                    println!(
                        "Applying {:?} relocation @ {:?} from segment start",
                        reloc.r#type, offset_into_segment
                    );

                    let reloc_addr: *mut u64 =
                        trans(real_segment_start.add(offset_into_segment.into()));
                    match reloc.r#type {
                        delf::RelType::Relative => {
                            let reloc_value = reloc.addend + delf::Addr(base as u64);
                            println!("Replacing with value {:?}", reloc_value);
                            *reloc_addr = reloc_value.0;
                        }
                        r#type => {
                            panic!("Unsupported relocation type {:?}", r#type);
                        }
                    }
                }
            }
        }

        println!("Adjusting permissions...");
        let mut protection = Protection::NONE;
        for flag in ph.flags.iter() {
            protection |= match flag {
                delf::SegmentFlag::Read => Protection::READ,
                delf::SegmentFlag::Write => Protection::WRITE,
                delf::SegmentFlag::Execute => Protection::EXECUTE,
            }
        }
        unsafe {
            protect(addr, len, protection)?;
        }
        mappings.push(map);
    }

    println!("Jumping to entry point @ {:?}...", file.entry_point);
    pause("jmp")?;
    unsafe {
        // jmp(file.entry_point.0 as _);
        // jmp((file.entry_point.0 as usize + base) as _);
        jmp(std::mem::transmute(file.entry_point.0 as usize + base));
    }
    Ok(())
}

unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}

// And this little helper function is new as well!
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
