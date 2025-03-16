use axtask::{TaskEXRef, current};

use crate::syscall_body;


pub fn sys_brk(addr: usize) -> isize {
    syscall_body!(sys_brk,{
        let current_task = current();
        let mut re_val: isize = current_task.task_ext().get_heap_top() as isize;
        let heap_bottm: usize = current_task.task_ext().get_heap_bottom() as usize;
        ///require the axconfig-gen to define the USER_HEAP_SIZE
        if addr != 0 && addr >= heap_bottm && addr <= heap_bottm + axconfig::plat::USER_HEAP_SIZE
        {
            current_task.task_ext().set_heap_top(addr as u64);
            re_val = addr as isize;
        }
        OK(re_val)
    })
}