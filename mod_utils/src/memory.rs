use lazy_static::lazy_static;
use std::borrow::BorrowMut;
use std::collections::HashMap;
use winapi::shared::minwindef::DWORD;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

pub struct MemoryProtection {
    protection_history: HashMap<usize, DWORD>,
}

// just contruct the class and we should be all set for storing the history

impl MemoryProtection {
    // Constructor
    pub fn new() -> Self {
        MemoryProtection {
            protection_history: HashMap::new(),
        }
    }

    // Function to toggle memory protection
    pub fn toggle_memory_protection(
        &mut self,
        protection_enabled: bool,
        address: usize,
        size: usize,
    ) -> bool {
        if protection_enabled && self.protection_history.contains_key(&address) {
            let old_protection = *self.protection_history.get(&address).unwrap();
            let mut dummy: DWORD = 0;
            let result =
                unsafe { VirtualProtect(address as *mut _, size, old_protection, &mut dummy) };
            if result == 0 {
                eprintln!("Failed to restore memory protection at {:X}", address);
                return false;
            }
            self.protection_history.remove(&address);
        } else if !protection_enabled && !self.protection_history.contains_key(&address) {
            let mut old_protection: DWORD = 0;
            let result = unsafe {
                VirtualProtect(
                    address as *mut _,
                    size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protection,
                )
            };
            if result == 0 {
                eprintln!("Failed to change memory protection at {:X}", address);
                return false;
            }
            self.protection_history.insert(address, old_protection);
        }
        true
    }

    pub fn mem_copy(&mut self, destination: usize, source: usize, num_bytes: usize) {
        if !self.toggle_memory_protection(false, destination, num_bytes) {
            eprintln!("Failed to disable memory protection for destination");
            return;
        }
        if !self.toggle_memory_protection(false, source, num_bytes) {
            eprintln!("Failed to disable memory protection for source");
            return;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(source as *const u8, destination as *mut u8, num_bytes);
        }

        if !self.toggle_memory_protection(true, source, num_bytes) {
            eprintln!("Failed to restore memory protection for source");
        }
        if !self.toggle_memory_protection(true, destination, num_bytes) {
            eprintln!("Failed to restore memory protection for destination");
        }
    }

    pub fn mem_set(&mut self, address: usize, byte: u8, num_bytes: usize) {
        if !self.toggle_memory_protection(false, address, num_bytes) {
            eprintln!("Failed to disable memory protection for address");
            return;
        }

        unsafe {
            std::ptr::write_bytes(address as *mut u8, byte, num_bytes);
        }

        if !self.toggle_memory_protection(true, address, num_bytes) {
            eprintln!("Failed to restore memory protection for address");
        }
    }
}
