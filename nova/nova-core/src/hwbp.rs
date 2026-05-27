use crate::process::Process;
use std::collections::HashMap;
use libc::c_void;

#[cfg(target_arch = "x86_64")]
const DR7_LOCAL_ENABLE_SHIFT: u64 = 0;
#[cfg(target_arch = "x86_64")]
const DR7_RW_SHIFT: u64 = 16;
#[cfg(target_arch = "x86_64")]
const DEBUG_REG_OFFSET_BASE: libc::c_long = 848;

pub struct HwBreakpointManager<'a> {
    process: &'a Process,
    active_bps: HashMap<usize, usize>,
}

impl<'a> HwBreakpointManager<'a> {
    pub fn new(process: &'a Process) -> Self {
        Self {
            process,
            active_bps: HashMap::new(),
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn set_exec_breakpoint(&mut self, addr: usize) -> Result<usize, String> {
        let pid = nix::unistd::Pid::from_raw(self.process.pid());

        let mut free_dr = None;
        for i in 0..4 {
            if !self.active_bps.contains_key(&i) {
                free_dr = Some(i);
                break;
            }
        }

        let dr_idx = free_dr.ok_or("No free debug registers available (max 4)")?;

        unsafe {
            let dr_offset = DEBUG_REG_OFFSET_BASE + (dr_idx as libc::c_long * 8);
            libc::ptrace(libc::PTRACE_POKEUSER, pid.as_raw(), dr_offset, addr as *mut c_void);

            let dr7_offset = DEBUG_REG_OFFSET_BASE + (7 * 8);

            let mut current_dr7 = libc::ptrace(libc::PTRACE_PEEKUSER, pid.as_raw(), dr7_offset, std::ptr::null_mut::<c_void>()) as u64;

            current_dr7 &= !(0b1111 << (DR7_RW_SHIFT + (dr_idx as u64 * 4)));
            current_dr7 |= 1 << (DR7_LOCAL_ENABLE_SHIFT + (dr_idx as u64 * 2));

            libc::ptrace(libc::PTRACE_POKEUSER, pid.as_raw(), dr7_offset, current_dr7 as *mut c_void);
        }

        self.active_bps.insert(dr_idx, addr);
        Ok(dr_idx)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn set_exec_breakpoint(&mut self, _addr: usize) -> Result<usize, String> {
        Err("ARM64 hardware breakpoints not fully implemented yet".to_string())
    }

    #[cfg(target_arch = "x86_64")]
    pub fn remove_breakpoint(&mut self, dr_idx: usize) -> Result<(), String> {
        if !self.active_bps.contains_key(&dr_idx) {
            return Err("Breakpoint not active".to_string());
        }

        let pid = nix::unistd::Pid::from_raw(self.process.pid());

        unsafe {
            let dr7_offset = DEBUG_REG_OFFSET_BASE + (7 * 8);
            let mut current_dr7 = libc::ptrace(libc::PTRACE_PEEKUSER, pid.as_raw(), dr7_offset, std::ptr::null_mut::<c_void>()) as u64;

            current_dr7 &= !(1 << (DR7_LOCAL_ENABLE_SHIFT + (dr_idx as u64 * 2)));

            libc::ptrace(libc::PTRACE_POKEUSER, pid.as_raw(), dr7_offset, current_dr7 as *mut c_void);

            let dr_offset = DEBUG_REG_OFFSET_BASE + (dr_idx as libc::c_long * 8);
            libc::ptrace(libc::PTRACE_POKEUSER, pid.as_raw(), dr_offset, std::ptr::null_mut::<c_void>());
        }

        self.active_bps.remove(&dr_idx);
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub fn remove_breakpoint(&mut self, _dr_idx: usize) -> Result<(), String> {
        Err("ARM64 hardware breakpoints not fully implemented yet".to_string())
    }
}
