// Opt out of libstd
#![no_std]
// Let us worry about the entry point.
#![no_main]
// Use the default allocation error handler
#![feature(default_alloc_error_handler)]
// Let us make functions without any prologue - assembly only!
#![feature(naked_functions)]
// Let us use inline assembly!
#![feature(asm)]
// Let us pass arguments to the linker directly
#![feature(link_args)]

/// Don't link any glibc stuff, also, make this executable static.
#[allow(unused_attributes)]
#[link_args = "-nostartfiles -nodefaultlibs -static"]
extern "C" {}

/// Our entry point.
#[naked]
#[no_mangle]
unsafe extern "C" fn _start() {
    asm!("mov rdi, rsp", "call pre_main", options(noreturn))
}

use encore::prelude::*;
use pixie::{Manifest, PixieError};

#[no_mangle]
unsafe fn pre_main(stack_top: *mut u8) {
    init_allocator();
    main(Env::read(stack_top)).unwrap();
    syscall::exit(0);
}

#[allow(clippy::unnecessary_wraps)]
fn main(env: Env) -> Result<(), PixieError> {
    println!("Hello from stage1!");

    let host = File::open("/proc/self/exe")?;
    let host = host.map()?;
    let host = host.as_ref();
    let manifest = Manifest::read_from_full_slice(host)?;

    let guest_range = manifest.guest.as_range();
    println!("The guest is at {:x?}", guest_range);

    let guest_slice = &host[guest_range];
    let uncompressed_guest =
        lz4_flex::decompress_size_prepended(guest_slice).expect("invalid lz4 payload");

    let tmp_path = "/tmp/minipak-guest";
    {
        let mut guest = File::create(tmp_path, 0o755)?;
        guest.write_all(&uncompressed_guest[..])?;
    }

    {
        extern crate alloc;
        // Make sure the path to execute is null-terminated
        let tmp_path_nullter = format!("{}\0", tmp_path);
        // Forward arguments and environment.
        let argv: Vec<*const u8> = env
            .args
            .iter()
            .copied()
            .map(str::as_ptr)
            .chain(core::iter::once(core::ptr::null()))
            .collect();
        let envp: Vec<*const u8> = env
            .vars
            .iter()
            .copied()
            .map(str::as_ptr)
            .chain(core::iter::once(core::ptr::null()))
            .collect();

        unsafe {
            asm!(
                "syscall",
                in("rax") 59, // `execve` syscall
                in("rdi") tmp_path_nullter.as_ptr(), // `filename`
                in("rsi") argv.as_ptr(), // `argv`
                in("rdx") envp.as_ptr(), // `envp`
                options(noreturn),
            )
        }
    }

    // If we comment that out, we get an error. If we don't, we get a warning.
    // Let's just allow the warning.
    #[allow(unreachable_code)]
    Ok(())
}
