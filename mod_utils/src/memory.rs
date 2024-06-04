use lazy_static::lazy_static;
use std::borrow::BorrowMut;
use std::collections::HashMap;
use winapi::shared::minwindef::DWORD;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

struct MemoryProtection {
    protection_history: HashMap<usize, DWORD>,
}

// just contruct the class and we should be all set for storing the history

impl MemoryProtection {
    pub fn new() -> Self {
        MemoryProtection {
            protection_history: HashMap::new(),
        }
    }
    pub fn toggle_memory_protection(
        &mut self,
        protection_enabled: bool,
        address: usize,
        size: usize,
    ) {
        if protection_enabled && self.protection_history.contains_key(&address) {
            let old_protection = self.protection_history.get(&address).unwrap();
            unsafe {
                VirtualProtect(
                    address as *mut _,
                    size,
                    *old_protection,
                    std::ptr::null_mut(),
                );
            }
            self.protection_history.remove(&address);
        } else if !protection_enabled && !self.protection_history.contains_key(&address) {
            let mut old_protection: DWORD = 0;
            unsafe {
                VirtualProtect(
                    address as *mut _,
                    size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protection as *mut DWORD,
                );
            }
            self.protection_history.insert(address, old_protection);
        }
    }

    fn mem_copy(&mut self, destination: usize, source: usize, num_bytes: usize) {
        Self::toggle_memory_protection(self, false, destination, num_bytes);
        Self::toggle_memory_protection(self, false, source, num_bytes);

        unsafe {
            std::ptr::copy_nonoverlapping(source as *const u8, destination as *mut u8, num_bytes);
        }

        Self::toggle_memory_protection(self, true, source, num_bytes);
        Self::toggle_memory_protection(self, true, destination, num_bytes);
    }

    fn mem_set(&mut self, address: usize, byte: u8, num_bytes: usize) {
        Self::toggle_memory_protection(self, false, address, num_bytes);

        unsafe {
            std::ptr::write_bytes(address as *mut u8, byte, num_bytes);
        }

        Self::toggle_memory_protection(self, true, address, num_bytes);
    }
}
