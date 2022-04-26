#![no_std]
#![no_main]
#![feature(default_alloc_error_handler)]
#![feature(naked_functions)]
#![feature(asm)]
#![feature(link_args)]

#[allow(unused_attributes)]
#[link_args = "-nostartfiles -nodefaultlibs -static"]
extern "C" {}

#[naked]
#[no_mangle]
unsafe extern "C" fn _start() {
    asm!("mov rdi, rsp", "call pre_main", options(noreturn))
}

extern crate alloc;

macro_rules! info {
    ($($tokens: tt)*) => {
        println!("[stage1] {}", alloc::format!($($tokens)*));
    }
}

use encore::prelude::*;
use pixie::{Manifest, PixieError};

extern "C" {
    fn i_do_not_exist();
}

#[no_mangle]
pub unsafe extern "C" fn entry() {
    i_do_not_exist();
}

#[no_mangle]
unsafe fn pre_main(stack_top: *mut u8) {
    init_allocator();
    main(stack_top, Env::read(stack_top)).unwrap();
    syscall::exit(0);
}

#[allow(clippy::unnecessary_wraps)]
fn main(stack_top: *mut u8, _env: Env) -> Result<(), PixieError> {
    let host = File::open("/proc/self/exe")?;
    let host = host.map()?;
    let host = host.as_ref();
    let manifest = Manifest::read_from_full_slice(host)?;

    let guest_range = manifest.guest.as_range();
    println!("The guest is at {:x?}", guest_range);

    let guest_slice = &host[guest_range];
    let uncompressed_guest =
        lz4_flex::decompress_size_prepended(guest_slice).expect("invalid lz4 payload");

    let guest_obj = Object::new(&uncompressed_guest[..])?;

    let guest_mapped = MappedObject::new(&guest_obj, None)?;
    info!("Mapped guest at 0x{:x}", guest_mapped.base());

    // Set phdr auxiliary vector
    let at_phdr = env.find_vector(AuxvType::PHDR);
    at_phdr.value = guest_mapped.base() + guest_obj.header().ph_offset;

    // Set phnum auxiliary vector
    let at_phnum = env.find_vector(AuxvType::PHNUM);
    at_phnum.value = guest_obj.header().ph_count as _;

    // Set entry auxiliary vector
    let at_entry = env.find_vector(AuxvType::ENTRY);
    at_entry.value = guest_mapped.base_offset() + guest_obj.header().entry_point;

    let entry_point = guest_mapped.base() + guest_obj.header().entry_point;
    info!("Jumping to guest's entry point 0x{:x}", entry_point);
    unsafe {
        pixie::launch(stack_top, entry_point);
    }
}
