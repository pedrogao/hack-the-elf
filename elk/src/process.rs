use enumflags2::BitFlags;
use mmap::{MapOption, MemoryMap};
use multimap::MultiMap;

use core::arch::asm;
use std::cmp::{max, min};
use std::collections::HashMap;
use std::ffi::CString;
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::{ops::Range, sync::Arc};

use crate::name::Name;

#[derive(Debug, Clone, Copy)]
#[repr(u64)]
pub enum AuxType {
    /// End of vector
    Null = 0,
    /// Entry should be ignored
    Ignore = 1,
    /// File descriptor of program
    ExecFd = 2,
    /// Program headers for program
    PHdr = 3,
    /// Size of program header entry
    PhEnt = 4,
    /// Number of program headers
    PhNum = 5,
    /// System page size
    PageSz = 6,
    /// Base address of interpreter
    Base = 7,
    /// Flags
    Flags = 8,
    /// Entry point of program
    Entry = 9,
    /// Program is not ELF
    NotElf = 10,
    /// Real uid
    Uid = 11,
    /// Effective uid
    EUid = 12,
    /// Real gid
    Gid = 13,
    /// Effective gid
    EGid = 14,
    /// String identifying CPU for optimizations
    Platform = 15,
    /// Arch-dependent hints at CPU capabilities
    HwCap = 16,
    /// Frequency at which times() increments
    ClkTck = 17,
    /// Secure mode boolean
    Secure = 23,
    /// String identifying real platform, may differ from Platform
    BasePlatform = 24,
    /// Address of 16 random bytes
    Random = 25,
    // Extension of HwCap
    HwCap2 = 26,
    /// Filename of program
    ExecFn = 31,

    SysInfo = 32,
    SysInfoEHdr = 33,
}

pub struct Auxv {
    typ: AuxType,
    value: u64,
}

impl Auxv {
    const KNOWN_TYPES: &'static [AuxType] = &[
        AuxType::ExecFd,
        AuxType::PHdr,
        AuxType::PhEnt,
        AuxType::PhNum,
        AuxType::PageSz,
        AuxType::Base,
        AuxType::Flags,
        AuxType::Entry,
        AuxType::NotElf,
        AuxType::Uid,
        AuxType::EUid,
        AuxType::Gid,
        AuxType::EGid,
        AuxType::Platform,
        AuxType::HwCap,
        AuxType::ClkTck,
        AuxType::Secure,
        AuxType::BasePlatform,
        AuxType::Random,
        AuxType::HwCap2,
        AuxType::ExecFn,
        AuxType::SysInfo,
        AuxType::SysInfoEHdr,
    ];

    pub fn get(typ: AuxType) -> Option<Self> {
        extern "C" {
            fn getauxval(typ: u64) -> u64;
        }

        unsafe {
            match getauxval(typ as u64) {
                0 => None,
                value => Some(Self { typ, value }),
            }
        }
    }

    pub fn get_known() -> Vec<Self> {
        Self::KNOWN_TYPES
            .iter()
            .copied()
            .filter_map(Self::get)
            .collect()
    }
}

pub struct StartOptions {
    pub exec_index: usize,
    pub args: Vec<CString>,
    pub env: Vec<CString>,
    pub auxv: Vec<Auxv>,
}

#[derive(Clone, Copy, Debug)]
pub enum RelocGroup {
    Direct,
    Indirect,
}

#[derive(Debug)]
pub struct ObjectRel<'a> {
    obj: &'a Object,
    rel: &'a delf::Rela,
}

impl ObjectRel<'_> {
    fn addr(&self) -> delf::Addr {
        self.obj.base + self.rel.offset
    }
}

#[derive(Debug, Clone)]
pub struct NamedSym {
    sym: delf::Sym,
    name: Name,
}

#[derive(Debug, Clone)]
pub struct ObjectSym<'a> {
    obj: &'a Object,
    sym: &'a NamedSym,
}

impl ObjectSym<'_> {
    fn value(&self) -> delf::Addr {
        let addr = self.sym.sym.value + self.obj.base;
        match self.sym.sym.r#type {
            delf::SymType::IFunc => unsafe {
                let src: extern "C" fn() -> delf::Addr = std::mem::transmute(addr);
                src()
            },
            _ => addr,
        }
    }
}

#[derive(Debug)]
pub enum ResolvedSym<'a> {
    Defined(ObjectSym<'a>),
    Undefined,
}

impl ResolvedSym<'_> {
    fn value(&self) -> delf::Addr {
        match self {
            Self::Defined(sym) => sym.value(),
            Self::Undefined => delf::Addr(0x0),
        }
    }

    fn size(&self) -> usize {
        match self {
            Self::Defined(sym) => sym.sym.sym.size as usize,
            Self::Undefined => 0,
        }
    }

    fn is_indirect(&self) -> bool {
        match self {
            Self::Undefined => false,
            Self::Defined(sym) => matches!(sym.sym.sym.r#type, delf::SymType::IFunc),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum LoadError {
    #[error("ELF object not found: {0}")]
    NotFound(String),
    #[error("An invalid or unsupported path was encountered")]
    InvalidPath(PathBuf),
    #[error("I/O error on {0}: {1}")]
    IO(PathBuf, std::io::Error),
    #[error("ELF object could not be parsed: {0}")]
    ParseError(PathBuf),
    #[error("ELF object has no load segments")]
    NoLoadSegments,
    #[error("ELF object could not be mapped in memory: {0}")]
    MapError(#[from] mmap::MapError),
    #[error("Could not read symbols from ELF object: {0}")]
    ReadSymsError(#[from] delf::ReadSymsError),
    #[error("Could not read relocations from ELF object: {0}")]
    ReadRelaError(#[from] delf::ReadRelaError),
}

#[derive(thiserror::Error, Debug)]
pub enum RelocationError {
    #[error("{0:?}: unimplemented relocation type {1:?}")]
    UnimplementedRelocation(PathBuf, delf::RelType),
    #[error("unknown symbol number: {0}")]
    UnknownSymbolNumber(u32),
    #[error("undefined symbol: {0:?}")]
    UndefinedSymbol(NamedSym),
}

pub enum GetResult {
    Cached(usize),
    Fresh(usize),
}

impl GetResult {
    fn fresh(self) -> Option<usize> {
        if let Self::Fresh(index) = self {
            Some(index)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct TLS {
    offsets: HashMap<delf::Addr, delf::Addr>,
    block: Vec<u8>,
    tcb_addr: delf::Addr,
}

pub struct Loader {
    pub search_path: Vec<PathBuf>,
    pub objects: Vec<Object>,
    pub objects_by_path: HashMap<PathBuf, usize>,
}

pub trait ProcessState {
    fn loader(&self) -> &Loader;
}

pub struct Loading {
    pub loader: Loader,
}

impl ProcessState for Loading {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

pub struct TLSAllocated {
    loader: Loader,
    pub tls: TLS,
}

impl ProcessState for TLSAllocated {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

pub struct Relocated {
    loader: Loader,
    tls: TLS,
}

impl ProcessState for Relocated {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

pub struct TLSInitialized {
    loader: Loader,
    tls: TLS,
}

impl ProcessState for TLSInitialized {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

impl Process<Relocated> {
    pub fn initialize_tls(self) -> Process<TLSInitialized> {
        let tls = &self.state.tls;

        for obj in &self.state.loader.objects {
            if let Some(ph) = obj.file.segment_of_type(delf::SegmentType::TLS) {
                if let Some(offset) = tls.offsets.get(&obj.base).cloned() {
                    unsafe {
                        (tls.tcb_addr - offset)
                            .write((ph.vaddr + obj.base).as_slice(ph.filesz.into()));
                    }
                }
            }
        }

        Process {
            state: TLSInitialized {
                loader: self.state.loader,
                tls: self.state.tls,
            },
        }
    }
}

#[derive(Debug)]
pub struct Process<S: ProcessState> {
    pub state: S,
}

impl Process<Loading> {
    pub fn new() -> Self {
        Self {
            state: Loading {
                loader: Loader {
                    objects: Vec::new(),
                    objects_by_path: HashMap::new(),
                    search_path: vec!["/usr/lib".into()],
                },
            },
        }
    }

    pub fn allocate_tls(mut self) -> Process<TLSAllocated> {
        let mut offsets = HashMap::new();
        let mut storage_space = 0;
        for obj in &mut self.state.loader.objects {
            let needed = obj
                .file
                .segment_of_type(delf::SegmentType::TLS)
                .map(|ph| ph.memsz.0)
                .unwrap_or_default() as u64;
            if needed > 0 {
                let offset = delf::Addr(storage_space + needed);
                offsets.insert(obj.base, offset);
                storage_space += needed;
            }
        }

        let storage_space = storage_space as usize;
        let tcbhead_size = 704; // per our GDB session
        let total_size = storage_space + tcbhead_size;

        let mut block = Vec::with_capacity(total_size);
        let tcb_addr = delf::Addr(block.as_ptr() as u64 + storage_space as u64);
        for _ in 0..storage_space {
            block.push(0u8);
        }

        block.extend(&tcb_addr.0.to_le_bytes()); // tcb
        block.extend(&0_u64.to_le_bytes()); // dtv
        block.extend(&tcb_addr.0.to_le_bytes()); // thread pointer
        block.extend(&0_u32.to_le_bytes()); // multiple_threads
        block.extend(&0_u32.to_le_bytes()); // gscope_flag
        block.extend(&0_u64.to_le_bytes()); // sysinfo
        block.extend(&0xDEADBEEF_u64.to_le_bytes()); // stack guard
        block.extend(&0xFEEDFACE_u64.to_le_bytes()); // pointer guard
        while block.len() < block.capacity() {
            block.push(0u8);
        }

        let tls = TLS {
            offsets,
            block: block,
            tcb_addr,
        };

        Process {
            state: TLSAllocated {
                loader: self.state.loader,
                tls,
            },
        }
    }

    fn build_stack(opts: &StartOptions) -> Vec<u64> {
        let mut stack = Vec::new();

        let null = 0_u64;

        macro_rules! push {
            ($x:expr) => {
                stack.push($x as u64)
            };
        }

        // argc
        push!(opts.args.len());

        // argv
        for v in &opts.args {
            push!(v.as_ptr());
        }
        push!(null);

        // envp
        for v in &opts.env {
            push!(v.as_ptr());
        }
        push!(null);

        // auxv
        for v in &opts.auxv {
            push!(v.typ);
            push!(v.value);
        }
        push!(AuxType::Null);
        push!(null);

        // align stack to 16-byte boundary
        if stack.len() % 2 == 1 {
            stack.push(0);
        }

        stack
    }

    pub fn load_object<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, LoadError> {
        let path = path
            .as_ref()
            .canonicalize()
            .map_err(|e| LoadError::IO(path.as_ref().to_path_buf(), e))?;

        let mut fs_file = std::fs::File::open(&path).map_err(|e| LoadError::IO(path.clone(), e))?;
        let mut input = Vec::new();
        fs_file
            .read_to_end(&mut input)
            .map_err(|e| LoadError::IO(path.clone(), e))?;

        println!("Loading {:?}", path);
        let file = delf::File::parse_or_print_error(input)
            .ok_or_else(|| LoadError::ParseError(path.clone()))?;

        let origin = path
            .parent()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?
            .to_str()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?;
        self.state.loader.search_path.extend(
            file.dynamic_entry_strings(delf::DynamicTag::RPath)
                .map(|path| String::from_utf8_lossy(path)) // new
                .map(|path| path.replace("$ORIGIN", &origin))
                .inspect(|path| println!("Found RPATH entry {:?}", path))
                .map(PathBuf::from),
        );
        let mem_range = file
            .program_headers
            .iter()
            .filter(|ph| ph.r#type == delf::SegmentType::Load)
            .map(|ph| ph.mem_range())
            .fold(None, |acc, range| match acc {
                None => Some(range),
                Some(acc) => Some(convex_hull(acc, range)),
            })
            .ok_or(LoadError::NoLoadSegments)?;

        let mem_size: usize = (mem_range.end - mem_range.start).into();
        let mem_map = std::mem::ManuallyDrop::new(MemoryMap::new(
            mem_size,
            &[MapOption::MapReadable, MapOption::MapWritable],
        )?);
        let base = delf::Addr(mem_map.data() as _) - mem_range.start;

        if path.to_str().unwrap().ends_with("libmsg.so") {
            let msg_addr: *const u8 = unsafe { (base + delf::Addr(0x2000)).as_ptr() };
            dbg!(msg_addr);
            let msg_slice = unsafe { std::slice::from_raw_parts(msg_addr, 0x26) };
            let msg = std::str::from_utf8(msg_slice).unwrap();
            dbg!(msg);
        }

        let load_segments = || {
            file.program_headers
                .iter()
                .filter(|ph| ph.r#type == delf::SegmentType::Load)
        };

        let segments = load_segments()
            .filter(|ph| ph.memsz.0 > 0)
            .map(|ph| -> Result<_, LoadError> {
                let vaddr = delf::Addr(ph.vaddr.0 & !0xFFF);
                let padding = ph.vaddr - vaddr;
                let offset = ph.offset - padding;
                let filesz = ph.filesz + padding;
                let map = MemoryMap::new(
                    filesz.into(),
                    &[
                        MapOption::MapReadable,
                        MapOption::MapWritable,
                        MapOption::MapFd(fs_file.as_raw_fd()),
                        MapOption::MapOffset(offset.into()),
                        MapOption::MapAddr(unsafe { (base + vaddr).as_ptr() }),
                    ],
                )?;

                if ph.memsz > ph.filesz {
                    let zero_start = base + ph.mem_range().start + ph.filesz;
                    let zero_len = ph.memsz - ph.filesz;
                    unsafe {
                        for i in zero_start.as_mut_slice::<u8>(zero_len.into()) {
                            *i = 0u8;
                        }
                    }
                }

                Ok(Segment {
                    map: Arc::new(map),
                    vaddr_range: vaddr..(ph.vaddr + ph.memsz),
                    padding,
                    flags: ph.flags,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let index = self.state.loader.objects.len();
        let syms = file.read_dynsym_entries()?;
        let syms: Vec<_> = if syms.is_empty() {
            vec![]
        } else {
            let dynstr = file
                .get_dynamic_entry(delf::DynamicTag::StrTab)
                .unwrap_or_else(|_| panic!("String table not found in {:?}", path));
            let segment = segments
                .iter()
                .find(|seg| seg.vaddr_range.contains(&dynstr))
                .unwrap_or_else(|| panic!("Segment not found for string table in {:#?}", path));

            syms.into_iter()
                .map(|sym| {
                    let name = Name::mapped(
                        &segment.map,
                        // a little bit of maths can't hurt
                        (dynstr + sym.name - segment.vaddr_range.start).into(),
                    );
                    NamedSym { sym, name }
                })
                .collect()
        };
        let mut sym_map = MultiMap::new();
        for sym in &syms {
            sym_map.insert(sym.name.clone(), sym.clone())
        }

        let mut rels = Vec::new();
        rels.extend(file.read_rela_entries()?);
        rels.extend(file.read_jmp_rel_entries()?);

        let mut initializers = Vec::new();
        if let Some(init) = file.dynamic_entry(delf::DynamicTag::Init) {
            let init = init + base;
            initializers.push(init);
        }

        if let Some(init_array) = file.dynamic_entry(delf::DynamicTag::InitArray) {
            if let Some(init_array_sz) = file.dynamic_entry(delf::DynamicTag::InitArraySz) {
                let init_array = base + init_array;
                let n = init_array_sz.0 as usize / std::mem::size_of::<delf::Addr>();

                let inits: &[delf::Addr] = unsafe { init_array.as_slice(n) };
                initializers.extend(inits.iter().map(|&init| init + base))
            }
        }

        let object = Object {
            path: path.clone(),
            base,
            segments,
            mem_range,
            file,
            syms,
            sym_map,
            rels,
            initializers,
        };

        self.state.loader.objects.push(object);
        self.state.loader.objects_by_path.insert(path, index);

        Ok(index)
    }

    pub fn adjust_protections(&self) -> Result<(), region::Error> {
        use region::{protect, Protection};

        for obj in &self.state.loader.objects {
            for seg in &obj.segments {
                let mut protection = Protection::NONE;
                for flag in seg.flags.iter() {
                    protection |= match flag {
                        delf::SegmentFlag::Read => Protection::READ,
                        delf::SegmentFlag::Write => Protection::WRITE,
                        delf::SegmentFlag::Execute => Protection::EXECUTE,
                    }
                }
                unsafe {
                    protect(seg.map.data(), seg.map.len(), protection)?;
                }
            }
        }
        Ok(())
    }

    pub fn load_object_and_dependencies<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<usize, LoadError> {
        let index = self.load_object(path)?;
        // TODO fix
        let mut a = vec![index];
        while !a.is_empty() {
            use delf::DynamicTag::Needed;
            a = a
                .into_iter()
                .map(|index| &self.state.loader.objects[index].file)
                .flat_map(|file| file.dynamic_entry_strings(Needed))
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect::<Vec<_>>()
                .into_iter()
                .map(|dep| self.get_object(&dep))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter_map(GetResult::fresh)
                .collect();
        }

        Ok(index)
    }

    pub fn get_object(&mut self, name: &str) -> Result<GetResult, LoadError> {
        let path = self.object_path(name)?;
        self.state
            .loader
            .objects_by_path
            .get(&path)
            .map(|&index| Ok(GetResult::Cached(index)))
            .unwrap_or_else(|| self.load_object(path).map(GetResult::Fresh))
    }

    pub fn object_path(&self, name: &str) -> Result<PathBuf, LoadError> {
        self.state
            .loader
            .search_path
            .iter()
            .filter_map(|prefix| prefix.join(name).canonicalize().ok())
            .find(|path| path.exists())
            .ok_or_else(|| LoadError::NotFound(name.into()))
    }

    pub fn patch_libc(&self) {
        let mut stub_map = std::collections::HashMap::<&str, Vec<u8>>::new();

        stub_map.insert(
            "_dl_addr",
            vec![
                0x48, 0x31, 0xc0, // xor rax, rax
                0xc3, // ret
            ],
        );

        stub_map.insert(
            "exit",
            vec![
                0x48, 0x31, 0xff, // xor rdi, rdi
                0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
                0x0f, 0x05, // syscall
            ],
        );

        let pattern = "/libc-2.";
        let libc = match self
            .state
            .loader
            .objects
            .iter()
            .find(|&obj| obj.path.to_string_lossy().contains(pattern))
        {
            Some(x) => x,
            None => {
                println!("Warning: could not find libc to patch!");
                return;
            }
        };

        for (name, instructions) in stub_map {
            let name = Name::owned(name);
            let sym = match libc.sym_map.get(&name) {
                Some(sym) => ObjectSym { obj: libc, sym },
                None => {
                    println!("expected to find symbol {:?} in {:?}", name, libc.path);
                    continue;
                }
            };
            println!("Patching libc function {:?} ({:?})", sym.value(), name);
            unsafe {
                sym.value().write(&instructions);
            }
        }
    }
}

impl Process<Protected> {
    pub fn start(self, opts: &StartOptions) -> ! {
        let exec = &self.state.loader.objects[opts.exec_index];
        let entry_point = exec.file.entry_point + exec.base;

        let stack = Self::build_stack(opts);
        let initializers = self.initializers();

        let argc = opts.args.len() as i32;
        let mut argv: Vec<_> = opts.args.iter().map(|x| x.as_ptr()).collect();
        argv.push(std::ptr::null());
        let mut envp: Vec<_> = opts.env.iter().map(|x| x.as_ptr()).collect();
        envp.push(std::ptr::null());

        unsafe {
            set_fs(self.state.tls.tcb_addr.0);

            #[allow(clippy::clippy::needless_range_loop)]
            for i in 0..initializers.len() {
                call_init(initializers[i].1, argc, argv.as_ptr(), envp.as_ptr());
            }

            jmp(entry_point.as_ptr(), stack.as_ptr(), stack.len())
        };
    }
}

impl<S> Process<S>
where
    S: ProcessState,
{
    fn initializers(&self) -> Vec<(&Object, delf::Addr)> {
        let mut res = Vec::new();

        for obj in self.state.loader().objects.iter().rev() {
            res.extend(obj.initializers.iter().map(|&init| (obj, init)));
        }

        res
    }
}

impl<S: ProcessState> Process<S> {
    fn lookup_symbol(&self, wanted: &ObjectSym, ignore_self: bool) -> ResolvedSym {
        for obj in &self.state.loader().objects {
            if ignore_self && std::ptr::eq(wanted.obj, obj) {
                continue;
            }

            if let Some(syms) = obj.sym_map.get_vec(&wanted.sym.name) {
                if let Some(sym) = syms.iter().find(|sym| !sym.sym.shndx.is_undef()) {
                    return ResolvedSym::Defined(ObjectSym { obj, sym });
                }
            }
        }
        ResolvedSym::Undefined
    }
}

impl Process<TLSAllocated> {
    pub fn apply_relocations(self) -> Result<Process<Relocated>, RelocationError> {
        let mut rels: Vec<_> = self
            .state
            .loader
            .objects
            .iter()
            .rev()
            .map(|obj| obj.rels.iter().map(move |rel| ObjectRel { obj, rel }))
            .flatten()
            .collect();

        for &group in &[RelocGroup::Direct, RelocGroup::Indirect] {
            println!("Applying {:?} relocations ({} left)", group, rels.len());
            rels = rels
                .into_iter()
                .map(|objrel| self.apply_relocation(objrel, group))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter_map(|x| x)
                .collect();
        }

        let res = Process {
            state: Relocated {
                loader: self.state.loader,
                tls: self.state.tls,
            },
        };

        Ok(res)
    }

    fn apply_relocation<'a>(
        &self,
        objrel: ObjectRel<'a>,
        group: RelocGroup,
    ) -> Result<Option<ObjectRel<'a>>, RelocationError> {
        use delf::RelType as RT;

        let ObjectRel { obj, rel } = objrel;
        let reltype = rel.r#type;
        let addend = rel.addend;

        let wanted = ObjectSym {
            obj,
            sym: &obj.syms[rel.sym as usize],
        };

        let ignore_self = matches!(reltype, RT::Copy);

        let found = match rel.sym {
            0 => obj.symzero(),
            _ => match self.lookup_symbol(&wanted, ignore_self) {
                undef @ ResolvedSym::Undefined => match wanted.sym.sym.bind {
                    delf::SymBind::Weak => undef,
                    _ => return Err(RelocationError::UndefinedSymbol(wanted.sym.clone())),
                },
                x => x,
            },
        };

        if let RelocGroup::Direct = group {
            if reltype == RT::IRelative || found.is_indirect() {
                return Ok(Some(objrel)); // deferred
            }
        }

        match reltype {
            RT::_64 => unsafe {
                objrel.addr().set(found.value() + addend);
            },
            RT::Relative => unsafe {
                objrel.addr().set(obj.base + addend);
            },
            RT::IRelative => unsafe {
                type Selector = unsafe extern "C" fn() -> delf::Addr;
                let selector: Selector = std::mem::transmute(obj.base + addend);
                objrel.addr().set(selector());
            },
            RT::Copy => unsafe {
                objrel.addr().write(found.value().as_slice(found.size()));
            },
            RT::GlobDat | RT::JumpSlot => unsafe {
                objrel.addr().set(found.value());
            },
            RT::TPOff64 => unsafe {
                if let ResolvedSym::Defined(sym) = found {
                    let obj_offset =
                        self.state
                            .tls
                            .offsets
                            .get(&sym.obj.base)
                            .unwrap_or_else(|| {
                                panic!(
                                    "No thread-local storage allocated for object {:?}",
                                    sym.obj.file
                                )
                            });
                    let obj_offset = -(obj_offset.0 as i64);
                    let offset =
                        obj_offset + sym.sym.sym.value.0 as i64 + objrel.rel.addend.0 as i64;
                    objrel.addr().set(offset);
                }
            },
        }
        Ok(None)
    }
}

pub struct Protected {
    loader: Loader,
    tls: TLS,
}

impl ProcessState for Protected {
    fn loader(&self) -> &Loader {
        &self.loader
    }
}

impl Process<TLSInitialized> {
    pub fn adjust_protections(self) -> Result<Process<Protected>, region::Error> {
        use region::{protect, Protection};

        for obj in &self.state.loader().objects {
            for seg in &obj.segments {
                let mut protection = Protection::NONE;
                for flag in seg.flags.iter() {
                    protection |= match flag {
                        delf::SegmentFlag::Read => Protection::READ,
                        delf::SegmentFlag::Write => Protection::WRITE,
                        delf::SegmentFlag::Execute => Protection::EXECUTE,
                    }
                }
                unsafe {
                    protect(seg.map.data(), seg.map.len(), protection)?;
                }
            }
        }

        Ok(Process {
            state: Protected {
                loader: self.state.loader,
                tls: self.state.tls,
            },
        })
    }
}

#[derive(custom_debug_derive::Debug)]
pub struct Segment {
    #[debug(skip)]
    pub map: Arc<MemoryMap>,
    pub vaddr_range: Range<delf::Addr>,
    pub padding: delf::Addr,
    pub flags: BitFlags<delf::SegmentFlag>,
}

#[derive(custom_debug_derive::Debug)]
pub struct Object {
    pub path: PathBuf,
    pub base: delf::Addr,
    #[debug(skip)]
    pub file: delf::File<Vec<u8>>,
    pub mem_range: Range<delf::Addr>,
    pub segments: Vec<Segment>,
    #[debug(skip)]
    pub syms: Vec<NamedSym>,
    #[debug(skip)]
    pub sym_map: MultiMap<Name, NamedSym>,
    #[debug(skip)]
    pub rels: Vec<delf::Rela>,
    #[debug(skip)]
    pub initializers: Vec<delf::Addr>,
}

impl Object {
    fn symzero(&self) -> ResolvedSym {
        ResolvedSym::Defined(ObjectSym {
            obj: &self,
            sym: &self.syms[0],
        })
    }
}

fn convex_hull(a: Range<delf::Addr>, b: Range<delf::Addr>) -> Range<delf::Addr> {
    (min(a.start, b.start))..(max(a.end, b.end))
}

fn dump_maps(msg: &str) {
    use std::{fs, process};

    println!("======== MEMORY MAPS: {}", msg);
    fs::read_to_string(format!("/proc/{pid}/maps", pid = process::id()))
        .unwrap()
        .lines()
        .filter(|line| line.contains("hello-dl") || line.contains("libmsg.so"))
        .for_each(|line| println!("{}", line));
    println!("=============================");
}

#[allow(named_asm_labels)]
#[inline(never)]
unsafe fn jmp(entry_point: *const u8, stack_contents: *const u64, qword_count: usize) {
    asm!(
        // allocate (qword_count * 8) bytes
        "mov {tmp}, {qword_count}",
        "sal {tmp}, 3",
        "sub rsp, {tmp}",

        ".l1:",
        // start at i = (n-1)
        "sub {qword_count}, 1",
        // copy qwords to the stack
        "mov {tmp}, QWORD PTR [{stack_contents}+{qword_count}*8]",
        "mov QWORD PTR [rsp+{qword_count}*8], {tmp}",
        // loop if i isn't zero, break otherwise
        "test {qword_count}, {qword_count}",
        "jnz .l1",

        "jmp {entry_point}",

        entry_point = in(reg) entry_point,
        stack_contents = in(reg) stack_contents,
        qword_count = in(reg) qword_count,
        tmp = out(reg) _,
    );
    asm!("ud2", options(noreturn));
}

#[inline(never)]
unsafe fn set_fs(addr: u64) {
    let syscall_number: u64 = 158;
    let arch_set_fs: u64 = 0x1002;

    asm!(
        "syscall",
        inout("rax") syscall_number => _,
        in("rdi") arch_set_fs,
        in("rsi") addr,
        lateout("rcx") _, lateout("r11") _,
    )
}

#[inline(never)]
unsafe fn call_init(addr: delf::Addr, argc: i32, argv: *const *const i8, envp: *const *const i8) {
    let init: extern "C" fn(argc: i32, argv: *const *const i8, envp: *const *const i8) =
        std::mem::transmute(addr.0);
    init(argc, argv, envp);
}
