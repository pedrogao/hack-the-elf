use custom_debug_derive::Debug as CustomDebug;
use mmap::MemoryMap;

use std::fs;
use std::path::PathBuf;

#[derive(Debug)]
pub struct Process {
    pub objects: Vec<Object>,
}

impl Process {
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
        }
    }

    pub fn load_object<P: AsRef<str>>(&mut self, path: P) -> Object {
        let input = fs::read(path.as_ref()).unwrap();
        let file = delf::File::parse_or_print_error(&input[..]).unwrap();
        let res = Object {
            path: path.as_ref().to_path_buf(),
            base: delf::Addr(0x400000),
            maps: Vec::new(),
            file,
        };
        res
    }
}

#[derive(custom_debug_derive::Debug)]
pub struct Object {
    // new!
    pub path: PathBuf,
    // new!
    pub base: delf::Addr,

    #[debug(skip)]
    pub file: delf::File,
    #[debug(skip)]
    pub maps: Vec<MemoryMap>,
}

#[derive(CustomDebug)]
pub struct Object {
    // we're skipping this one because it would get *real* verbose
    #[debug(skip)]
    pub file: delf::File,

    // `MemoryMap` does not implement `Debug`, so we need to skip it.
    // if we weren't using `custom_debug_derive`, we would have to do an
    // entirely custom `fmt::Debug` implementation for `Object`!
    #[debug(skip)]
    pub maps: Vec<MemoryMap>,
}
