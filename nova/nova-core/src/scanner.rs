pub struct Signature {
    pub pattern: Vec<Option<u8>>,
}

impl Signature {
    /// Parses an IDA-style signature like "48 8B 05 ? ? ? ? 48 85 C0"
    pub fn parse(sig: &str) -> Result<Self, String> {
        let mut pattern = Vec::new();

        for part in sig.split_whitespace() {
            if part == "?" || part == "??" {
                pattern.push(None);
            } else {
                let byte = u8::from_str_radix(part, 16)
                    .map_err(|_| format!("Invalid byte in signature: {}", part))?;
                pattern.push(Some(byte));
            }
        }

        if pattern.is_empty() {
            return Err("Empty signature".to_string());
        }

        Ok(Self { pattern })
    }

    /// Finds the first occurrence of the signature in the given buffer
    pub fn find(&self, buffer: &[u8]) -> Option<usize> {
        if self.pattern.is_empty() || buffer.len() < self.pattern.len() {
            return None;
        }

        let first_byte = match self.pattern.iter().find(|&&x| x.is_some()) {
            Some(Some(b)) => *b,
            _ => return Some(0), // Signature is all wildcards...
        };

        let first_idx = self.pattern.iter().position(|x| x.is_some()).unwrap();

        let max_search_idx = buffer.len() - self.pattern.len();

        for i in 0..=max_search_idx {
            if buffer[i + first_idx] == first_byte {
                let mut matches = true;
                for (j, &pat_byte) in self.pattern.iter().enumerate() {
                    if let Some(b) = pat_byte {
                        if buffer[i + j] != b {
                            matches = false;
                            break;
                        }
                    }
                }
                if matches {
                    return Some(i);
                }
            }
        }
        None
    }
}
