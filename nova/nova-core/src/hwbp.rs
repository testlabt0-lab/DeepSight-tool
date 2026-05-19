use crate::process::Process;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use libc::{user_regs_struct, c_void};
use std::collections::HashMap;

// Constants for Hardware Breakpoints (x86_64 Debug Registers)
const DR7_LOCAL_ENABLE_SHIFT: u64 = 0;
const DR7_RW_SHIFT: u64 = 16;
const DR7_LEN_SHIFT: u64 = 18;

// Debug register indices for ptrace PEEKUSER/POKEUSER
// On Linux x86_64, debug registers are accessed via offset in the USER area.
// offset = offsetof(struct user, u_debugreg[N])
// In `libc`, these constants might not be directly exposed for POKEUSER easily,
// but they map to specific offsets.
// A simpler way on modern Linux is `ptrace(PTRACE_SET_DEBUGREG, pid, offset, data)`
// OR using the newer `PTRACE_SETREGSET` with `NT_X86_XSTATE`.
// But the traditional `POKEUSER` is at offset: `offsetof(struct user, u_debugreg[n])`
// For x86_64, `offsetof(struct user, u_debugreg[0])` is 848 (0x350).
const DEBUG_REG_OFFSET_BASE: libc::c_long = 848;

pub struct HwBreakpointManager<'a> {
    process: &'a Process,
    active_bps: HashMap<usize, usize>, // maps DR index (0-3) to address
}

impl<'a> HwBreakpointManager<'a> {
    pub fn new(process: &'a Process) -> Self {
        Self {
            process,
            active_bps: HashMap::new(),
        }
    }

    /// Set a hardware execution breakpoint at `addr`.
    /// Does not modify the code memory at all.
    pub fn set_exec_breakpoint(&mut self, addr: usize) -> Result<usize, String> {
        let pid = nix::unistd::Pid::from_raw(self.process.pid());

        // Find a free debug register (DR0-DR3)
        let mut free_dr = None;
        for i in 0..4 {
            if !self.active_bps.contains_key(&i) {
                free_dr = Some(i);
                break;
            }
        }

        let dr_idx = free_dr.ok_or("No free debug registers available (max 4)")?;

        unsafe {
            // Set DRn to the address
            let dr_offset = DEBUG_REG_OFFSET_BASE + (dr_idx as libc::c_long * 8);
            libc::ptrace(libc::PTRACE_POKEUSER, pid.as_raw(), dr_offset, addr as *mut c_void);

            // Update DR7 (Control Register)
            // We need to enable Local Breakpoint for DRn, and set type to Execution (00) and len to 1 (00)
            let dr7_offset = DEBUG_REG_OFFSET_BASE + (7 * 8);

            // Read current DR7
            let mut current_dr7 = libc::ptrace(libc::PTRACE_PEEKUSER, pid.as_raw(), dr7_offset, std::ptr::null_mut::<c_void>()) as u64;

            // Clear RW and LEN bits for this DRn (Execution, 1 byte)
            current_dr7 &= !(0b1111 << (DR7_RW_SHIFT + (dr_idx as u64 * 4)));

            // Set Local Enable bit for this DRn
            current_dr7 |= 1 << (DR7_LOCAL_ENABLE_SHIFT + (dr_idx as u64 * 2));

            // Write back DR7
            libc::ptrace(libc::PTRACE_POKEUSER, pid.as_raw(), dr7_offset, current_dr7 as *mut c_void);
        }

        self.active_bps.insert(dr_idx, addr);
        Ok(dr_idx)
    }

    /// Removes a hardware breakpoint by its DR index
    pub fn remove_breakpoint(&mut self, dr_idx: usize) -> Result<(), String> {
        if !self.active_bps.contains_key(&dr_idx) {
            return Err("Breakpoint not active".to_string());
        }

        let pid = nix::unistd::Pid::from_raw(self.process.pid());

        unsafe {
            let dr7_offset = DEBUG_REG_OFFSET_BASE + (7 * 8);
            let mut current_dr7 = libc::ptrace(libc::PTRACE_PEEKUSER, pid.as_raw(), dr7_offset, std::ptr::null_mut::<c_void>()) as u64;

            // Clear Local Enable bit
            current_dr7 &= !(1 << (DR7_LOCAL_ENABLE_SHIFT + (dr_idx as u64 * 2)));

            libc::ptrace(libc::PTRACE_POKEUSER, pid.as_raw(), dr7_offset, current_dr7 as *mut c_void);

            // Clear DRn
            let dr_offset = DEBUG_REG_OFFSET_BASE + (dr_idx as libc::c_long * 8);
            libc::ptrace(libc::PTRACE_POKEUSER, pid.as_raw(), dr_offset, std::ptr::null_mut::<c_void>());
        }

        self.active_bps.remove(&dr_idx);
        Ok(())
    }
}
