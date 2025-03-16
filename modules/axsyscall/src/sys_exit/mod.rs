use core::arch::asm;

pub fn sys_exit(status: u32) -> ! {
    unsafe {
        asm!(
            "syscall",
            in   }
    loop {}
    
}