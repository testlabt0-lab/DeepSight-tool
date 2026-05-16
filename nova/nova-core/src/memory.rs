use std::fs::File;
use std::io::{self, BufRead, BufReader};


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub shared: bool,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: usize,
    pub end: usize,
    pub permissions: MemoryPermissions,
    pub offset: usize,
    pub pathname: String,
}

impl MemoryRegion {
    pub fn size(&self) -> usize {
        self.end - self.start
    }
}

pub fn get_memory_maps(pid: i32) -> io::Result<Vec<MemoryRegion>> {
    let path = format!("/proc/{}/maps", pid);
    let file = File::open(&path)?;
    let reader = BufReader::new(file);
    let mut regions = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if let Some(region) = parse_maps_line(&line) {
            regions.push(region);
        }
    }

    Ok(regions)
}

fn parse_maps_line(line: &str) -> Option<MemoryRegion> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }

    let addr_parts: Vec<&str> = parts[0].split('-').collect();
    if addr_parts.len() != 2 {
        return None;
    }

    let start = usize::from_str_radix(addr_parts[0], 16).ok()?;
    let end = usize::from_str_radix(addr_parts[1], 16).ok()?;

    let perms = parts[1];
    let permissions = MemoryPermissions {
        read: perms.chars().nth(0) == Some('r'),
        write: perms.chars().nth(1) == Some('w'),
        execute: perms.chars().nth(2) == Some('x'),
        shared: perms.chars().nth(3) == Some('s'),
    };

    let offset = usize::from_str_radix(parts[2], 16).ok()?;

    let pathname = if parts.len() >= 6 {
        parts[5..].join(" ")
    } else {
        String::new()
    };

    Some(MemoryRegion {
        start,
        end,
        permissions,
        offset,
        pathname,
    })
}
