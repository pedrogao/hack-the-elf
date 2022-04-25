use bitflags::*;

bitflags! {
    /// Memory protection: readable, writable, executable
    #[derive(Default)]
    pub struct MmapProt: u64 {
        /// The mapping will be readable
        const READ = 0x1;
        /// The mapping will be writable
        const WRITE = 0x2;
        /// The mapping will be executable
        const EXEC = 0x4;
    }
}

bitflags! {
    /// Flags for the `mmap` syscall
    pub struct MmapFlags: u64 {
        /// Create a private copy-on-write mapping.
        const PRIVATE = 0x02;
        /// Don't interpret addr as a hint: place the mapping at exactly that address.
        const FIXED = 0x10;
        /// Mapping is not backed by any file
        const ANONYMOUS = 0x20;
    }
}

bitflags! {
    /// Flags for the `open` syscall
    pub struct OpenFlags: u64 {
        /// Read-only (open flag)
        const RDONLY = 0o0;
        /// Read-write (open flag)
        const RDWR = 0o2;
        /// Create (open flag)
        const CREAT = 0o100;
        /// Truncate (open flag)
        const TRUNC = 0o1000;
    }
}

#[inline(always)]
pub unsafe fn open(filename: *const u8, flags: OpenFlags, mode: u64) -> FileDescriptor {
    let syscall_number: u64 = 2;
    let mut rax = syscall_number;

    asm!(
        "syscall",
        inout("rax") rax,
        in("rdi") filename,
        in("rsi") flags.bits(),
        in("rdx") mode,
        lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    FileDescriptor(rax)
}

#[repr(C)]
pub struct Stat {
    // As found using `offsetof` and `sizeof`
    _unused1: [u8; 48],
    pub size: u64,
    _unused2: [u8; 88],
}

/// # Safety
/// Calls into the kernel.
#[inline(always)]
pub unsafe fn fstat(fd: FileDescriptor, buf: *mut Stat) -> u64 {
    let syscall_number: u64 = 5;
    let mut rax = syscall_number;

    asm!(
        "syscall",
        inout("rax") rax,
        in("rdi") fd.0,
        in("rsi") buf,
        lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    rax
}

#[inline(always)]
pub unsafe fn mmap(
    addr: u64,
    len: u64,
    prot: MmapProt,
    flags: MmapFlags,
    fd: FileDescriptor,
    off: u64,
) -> u64 {
    let syscall_number: u64 = 9;
    let mut rax = syscall_number;

    asm!(
        "syscall",
        inout("rax") rax,
        in("rdi") addr,
        in("rsi") len,
        in("rdx") prot.bits(),
        in("r10") flags.bits(),
        in("r8") fd.0,
        in("r9") off,
        lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    rax
}

#[inline(always)]
pub unsafe fn munmap<T>(addr: *const T, len: u64) -> u64 {
    let syscall_number: u64 = 11;
    let mut rax = syscall_number;

    asm!(
        "syscall",
        inout("rax") rax,
        in("rdi") addr,
        in("rsi") len,
        lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    rax
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileDescriptor(pub u64);

impl FileDescriptor {
    /// Standard input file descriptor
    pub const STDIN: Self = Self(0);
    /// Standard output file descriptor
    pub const STDOUT: Self = Self(1);
    /// Standard error file descriptor
    pub const STDERR: Self = Self(2);
}

/// # Safety
/// Calls into the kernel.
#[inline(always)]
pub unsafe fn write(fd: FileDescriptor, buf: *const u8, count: u64) -> u64 {
    let syscall_number: u64 = 1;
    let mut rax = syscall_number;

    asm!(
        "syscall",
        inout("rax") rax,
        in("rdi") fd.0,
        in("rsi") buf,
        in("rdx") count,
        lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    rax
}

#[inline(always)]
pub fn exit(code: i32) -> ! {
    let syscall_number: u64 = 60;
    unsafe {
        asm!(
            "syscall",
            in("rax") syscall_number,
            in("rdi") code,
            options(noreturn, nostack),
        );
    }
}

#[inline(always)]
pub unsafe fn close(fd: FileDescriptor) -> u64 {
    let syscall_number: u64 = 3;
    let mut rax = syscall_number;

    asm!(
        "syscall",
        inout("rax") rax,
        in("rdi") fd.0,
        lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    rax
}
