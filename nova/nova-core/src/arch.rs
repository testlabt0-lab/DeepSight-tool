#[cfg(target_arch = "x86_64")]
pub mod x86_64 {
    pub const INT3: u8 = 0xCC;
    pub const DEBUG_REG_OFFSET_BASE: libc::c_long = 848;
}

#[cfg(target_arch = "aarch64")]
pub mod aarch64 {
    // AArch64 uses BRK for breakpoints, typically `BRK #0` is 0xD4200000 (little endian)
    // Here we might just define the bytes
    pub const BRK_BYTES: [u8; 4] = [0x00, 0x00, 0x20, 0xD4];

    // On AArch64, debug registers are accessed via PTRACE_GETREGSET with NT_ARM_HW_BREAK
    // rather than PEEKUSER. So the HWBP module will need a total rewrite for aarch64.
}
