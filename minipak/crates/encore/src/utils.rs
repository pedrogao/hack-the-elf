use core::fmt;

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {
        {
            use ::core::fmt::Write;
            ::core::writeln!($crate::utils::Stdout, $($arg)*).ok();
        }
    }
}

pub struct Stdout;
impl fmt::Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        unsafe {
            crate::syscall::write(
                crate::syscall::FileDescriptor::STDOUT,
                s.as_ptr(),
                s.len() as _,
            );
        }
        Ok(())
    }
}

pub trait NullTerminated
where
    Self: Sized,
{
    unsafe fn null_terminated(self) -> &'static [u8];

    unsafe fn cstr(self) -> &'static str {
        core::str::from_utf8(self.null_terminated()).unwrap()
    }
}

impl NullTerminated for *const u8 {
    unsafe fn null_terminated(self) -> &'static [u8] {
        let mut j = 0;
        while *self.add(j) != 0 {
            j += 1;
        }
        core::slice::from_raw_parts(self, j)
    }
}
