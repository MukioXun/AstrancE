//! syscall impl for AstrancE
// #![no_std]
#![cfg_attr(not(test), no_std)]
// #![cfg(test)]

mod test;
#[macro_use]
extern crate axlog;
use syscalls::Sysno;
mod syscall_imp;
use core::ffi::*;
use arceos_posix_api::ctypes;
use syscall_imp::errno::LinuxError;

///SyscallResult 可直接into为有符号整数，其中错误值以负数返回，linuxError有
/// 方法as_str返回对应错误的具体文字描述
pub enum SyscallResult{ Success(isize), Error(LinuxError) }

impl From<SyscallResult> for isize {
    fn from(result: SyscallResult) -> isize {
        match result {
            SyscallResult::Success(val) => val as isize,
            SyscallResult::Error(e) => {
                -(e as isize)
            }
        }
    }
}

pub enum SyscallErr {
    Unimplemented
}

pub fn syscall_handler(sys_id: usize, args: [usize; 6]) -> Result<SyscallResult, SyscallErr> {
    let sys_id = Sysno::from(sys_id as u32);//检查id与测例是否适配

    let ret = match sys_id {
        Sysno::write => {
            let [fd, buf_ptr, size, ..] = args;
            let buf = unsafe { core::slice::from_raw_parts(buf_ptr as _ , size) };
            syscall_imp::io::sys_write(fd, buf)
        }

        Sysno::read => {
            let [fd, buf_ptr, size, ..] = args;
            let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, size) };
                syscall_imp::io::sys_read(fd, buf)
        }

        Sysno::writev =>{
            let [fd,iov,iocnt,..] = args;
            syscall_imp::io::sys_writev(fd as _,iov as _,iocnt as _)
        }
        // 文件操作相关系统调用
        #[cfg(all(feature = "fs", feature = "fd"))]
        Sysno::openat => {
            let [dirfd,fname, flags,mode,..] = args;
            syscall_imp::fs::sys_openat(dirfd as _,fname as _,flags as _,mode as _)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        Sysno::close => {
            let fd =args[0];
            syscall_imp::fd::sys_close(fd as _)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        Sysno::statfs => {
            todo!()
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        Sysno::fstat => {
            let [fd,buf,..] = args;
            unsafe { syscall_imp::fs::sys_fstat(fd as _, buf as _) }
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        Sysno::lseek => {
            let [fd,offset,whence,..] = args;
            syscall_imp::fs::sys_lseek(fd as _,offset as _,whence as _)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        Sysno::getcwd => {
            let [buf,size,..] = args;
            syscall_imp::fs::sys_getcwd(buf as _,size as _)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        Sysno::renameat => {
            let [old,new,..] = args;
            syscall_imp::fs::sys_rename(old as _,new as _)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        Sysno::dup => {
            let old_fd = args[0];
            syscall_imp::fd::sys_dup(old_fd as _)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        Sysno::dup3 => {
            let [old_fd,new_fd,..] = args;
            syscall_imp::fd::sys_dup3(old_fd as _,new_fd as _)
        }

        #[cfg(all(feature = "fs", feature = "fd"))]
        Sysno::fcntl => {
            let [fd,cmd,arg,..] = args;
            syscall_imp::fd::sys_fcntl(fd as _,cmd as _,arg as _)
        }
        #[cfg(feature = "pipe")]
        Sysno::pipe2 =>{
            // let fds = args[0];
            // syscall_imp::pipe::sys_pipe(fds as _);
            //此处fds无法自发完成usize向&mut [c_int]的转换，需要自定义切片类型并完成转换！！！！
            todo!()
        }
        Sysno::mmap => {
            todo!()
        }

        Sysno::munmap => {
            todo!()
        }

        // 进程控制相关系统调用
        Sysno::exit => {
            let code = args[0];
            syscall_imp::task::sys_exit(code as _)
        }
        Sysno::getpid => {
            syscall_imp::task::sys_getpid()
        }
        Sysno::clone => {
            return Err(SyscallErr::Unimplemented);
        }
        Sysno::execve => {
            return Err(SyscallErr::Unimplemented);
        },
        Sysno::wait4 => {
            return Err(SyscallErr::Unimplemented);
        }
        Sysno::sched_yield => {
            syscall_imp::task::sys_yield()
        }
        // 时间相关系统调用
        Sysno::clock_gettime | Sysno::clock_gettime64 => {
            let cls = args[0];
            let ts: *mut ctypes::timespec= args[1] as *mut ctypes::timespec;
            syscall_imp::time::sys_clock_gettime(cls as ctypes::clockid_t, ts)
        }
        Sysno::gettimeofday => {
            let ts: *mut ctypes::timeval= args[0] as *mut ctypes::timeval;
            syscall_imp::time::sys_get_time_of_day(ts)
        }
        Sysno::nanosleep  => {
            let req : *const ctypes::timespec = args[0] as *const ctypes::timespec;
            let rem: *mut ctypes::timespec = args[1] as *mut ctypes::timespec;
            syscall_imp::time::sys_nanosleep(req, rem)
        }
         Sysno::clock_nanosleep_time64 => {
            // TODO: handle clock_id and flags
            let _clock_id = args[0];
            let _flags = args[1];
            let req : *const ctypes::timespec = args[2] as *const ctypes::timespec;
            let rem: *mut ctypes::timespec = args[3] as *mut ctypes::timespec;
            syscall_imp::time::sys_nanosleep(req, rem)

        }
        // 其他系统调用
        Sysno::brk => {
            return Err(SyscallErr::Unimplemented);
        }
        Sysno::uname => {
            todo!()
        }

        Sysno::chdir => {
            todo!()
        }
        Sysno::mkdirat => {
            todo!()
        }
        Sysno::getdents64 => {
            todo!()
        }

        //网络相关
        #[cfg(feature = "net")]
        Sysno::socket => {
            let [domain,socktype,protocol,..] =args;
            syscall_imp::net::sys_socket(domain as _, socktype as _, protocol as _)
        }
        #[cfg(feature = "net")]
        Sysno::bind => {
            let [fd,addr,addrlen,..] = args;
            syscall_imp::net::sys_bind(fd as _, addr as _, addrlen as _)
        }
        #[cfg(feature = "net")]
        // fd, addr, addrlen
        Sysno::connect => {
            let [fd,addr,addrlen,..] = args;
            syscall_imp::net::sys_connect(fd as _, addr as _, addrlen as _)
        }
        #[cfg(feature = "net")]
        // fd, buf, len, flags, addr, addrlen
        Sysno::sendto => {
            let [fd, buf, len, flags, addr, addrlen, ..] = args;
            syscall_imp::net::sys_sendto(fd as _, buf as _, len as _, flags as _, addr as _, addrlen as _)
        }

        #[cfg(feature = "net")]
        // fd, buf, len, flags
        Sysno::sendmsg => {
            let [fd, buf, len, flags, ..] = args;
            syscall_imp::net::sys_send(fd as _, buf as _, len as _, flags as _)
        }

        #[cfg(feature = "net")]
        // fd, buf, len, flags, addr, addrlen
        Sysno::recvfrom => {
            let [fd, buf, len, flags, addr, addrlen, ..] = args;
            unsafe { syscall_imp::net::sys_recvfrom(fd as _, buf as _, len as _, flags as _, addr as _, addrlen as _) }
        }

        #[cfg(feature = "net")]
        // fd, buf, len, flags
        Sysno::recvmsg => {
            let [fd, buf, len, flags, ..] = args;
            syscall_imp::net::sys_recv(fd as _, buf as _, len as _, flags as _)
        }

        #[cfg(feature = "net")]
        // fd, backlog
        Sysno::listen => {
            let [fd, backlog, ..] = args;
            syscall_imp::net::sys_listen(fd as _, backlog as _)
        }

        #[cfg(feature = "net")]
        // fd, addr, addrlen
        Sysno::accept => {
            let [fd, addr, addrlen, ..] = args;
            unsafe { syscall_imp::net::sys_accept(fd as _, addr as _, addrlen as _) }
        }

        #[cfg(feature = "net")]
        // fd, how
        Sysno::shutdown => {
            let [fd, how, ..] = args;
            syscall_imp::net::sys_shutdown(fd as _, how as _)
        }

        #[cfg(feature = "net")]
        // fd, addr, addrlen
        Sysno::getsockname => {
            let [fd, addr, addrlen, ..] = args;
            unsafe { syscall_imp::net::sys_getsockname(fd as _, addr as _, addrlen as _) }
        }

        #[cfg(feature = "net")]
        // fd, addr, addrlen
        Sysno::getpeername => {
            let [fd, addr, addrlen, ..] = args;
            unsafe { syscall_imp::net::sys_getpeername(fd as _, addr as _, addrlen as _) }
        }


        _ => {
            return Err(SyscallErr::Unimplemented);
        }
    };

    Ok(ret)
}
