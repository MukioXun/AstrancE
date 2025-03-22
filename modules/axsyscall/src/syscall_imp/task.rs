use arceos_posix_api::{self as api, ctypes};
use core::ffi::c_char;
use core::ffi::c_int;
use core::ffi::c_void;
use crate::SyscallResult;

pub fn ax_getpid() -> SyscallResult {
    let ret = api::sys_getpid() as isize;
    SyscallResult::Success(ret)
}

pub fn ax_exit(code:c_int) -> SyscallResult{
    api::sys_exit(code);
    SyscallResult::Success(2)
}

pub fn ax_yield() -> SyscallResult{
    SyscallResult::Success(api::sys_sched_yield() as isize)
}