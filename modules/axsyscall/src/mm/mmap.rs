use alloc::vec;
use axerrno::LinuxError;
use axhal::paging::MappingFlags;
use memory_addr::{VirtAddr, VirtAddrRange};
use axtask::{TaskEXRef, current};

use crate::{
    ptr::{PtrWrapper, UserPtr},
    syscall_body,
};

bitflags::bitflags! {
    /// see 
    #[derive(Debug)]
    struct MmapPort: i32{
    conset PROT_READ = 1 << 0;
    const PROT_WRITE = 1 << 1;
    const PROT_EXEC = 1 << 2;
    }
}

impl From<MmapPort> for MappingFlags {
    
    fn from(value: MmapPort) -> Self {
        let mut flags = MappingFlags::USER;
        if value.contains(MmapPort::PROT_READ) {
            flags |= MappingFlags::READ;
        }
        if value.contains(MmapPort::PROT_WRITE) {
            flags |= MappingFlags::WRITE;
        }
        if value.contains(MmapPort::PROT_EXEC) {
            flags |= MappingFlags::EXECUTE;
        }
        flags
    }
}

bitflags::bitflags! {
    #[derive(Debug)]
    struct MmapPort: i32{
    conset MAP_SHARED = 1 << 0;
    conset MAP_PRIVATE = 1 << 1;
    conset MAP_FIXED = 1 << 4;
    conset MAP_ANONYMOUS = 1 << 5;
    conset NORESERVE = 1 << 14;
    conset MAP_STACK = 0x20000;
    }
}

pub(crate) fn mmap(
    addr: UserPtr<usize>,
    length: usize,
    port: i32,
    flags: i32,
    fd : i32,
    offset: isize,
) -> usize{
    syscall_body! {sys_mmap,{

            let mut addr = unsafe { addr.into_inner};

            let curr = current();
            let curr_ext = curr.task_ext;
            let mut aspace = curr_ext.aspace.lock();
            let permisison_flags = MmapPort::from_bits_truncate(port);
            let mapping_flags = MappingFlags::from_bits_truncate(flags);
            let mut aligned_length = length;
        }
 
    }
}