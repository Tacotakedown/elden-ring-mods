use lazy_static::lazy_static;
use std::borrow::BorrowMut;
use std::collections::HashMap;
use winapi::shared::minwindef::DWORD;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

use crate::aob::{
    check_if_aobs_match, raw_aob_to_string_aob, string_aob_to_raw_aob, tokenify_aob_string,
    verify_aobs,
};

pub struct MemoryProtection {
    protection_history: HashMap<u8, DWORD>,
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
        address: &mut u8,
        size: usize,
    ) -> bool {
        if protection_enabled && self.protection_history.contains_key(&address) {
            let old_protection = *self.protection_history.get(&address).unwrap();
            let mut dummy: DWORD = 0;
            let result =
                unsafe { VirtualProtect(*address as *mut _, size, old_protection, &mut dummy) };
            if result == 0 {
                eprintln!("Failed to restore memory protection at {:X}", address);
                return false;
            }
            self.protection_history.remove(&address);
        } else if !protection_enabled && !self.protection_history.contains_key(&address) {
            let mut old_protection: DWORD = 0;
            let result = unsafe {
                VirtualProtect(
                    *address as *mut _,
                    size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protection,
                )
            };
            if result == 0 {
                eprintln!("Failed to change memory protection at {:X}", address);
                return false;
            }
            self.protection_history.insert(*address, old_protection);
        }
        true
    }

    pub fn mem_copy(&mut self, destination: &mut u8, source: &mut u8, num_bytes: usize) {
        if !self.toggle_memory_protection(false, destination, num_bytes) {
            eprintln!("Failed to disable memory protection for destination");
            return;
        }
        if !self.toggle_memory_protection(false, source, num_bytes) {
            eprintln!("Failed to disable memory protection for source");
            return;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(source, destination, num_bytes);
        }

        if !self.toggle_memory_protection(true, source, num_bytes) {
            eprintln!("Failed to restore memory protection for source");
        }
        if !self.toggle_memory_protection(true, destination, num_bytes) {
            eprintln!("Failed to restore memory protection for destination");
        }
    }

    pub fn mem_set(&mut self, address: &mut u8, byte: u8, num_bytes: usize) {
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

pub fn replace_expected_bytes_at_address(
    address: usize,
    expected_bytes: &str,
    new_bytes: &str,
    memory_manager: &mut MemoryProtection,
) -> bool {
    // if !verify_aobs(expected_bytes, new_bytes) {
    //     return false;
    // }

    let expected_bytes_tokens = tokenify_aob_string(expected_bytes);
    let mut existing_bytes_buffer = vec![0u8; expected_bytes_tokens.len()];
    unsafe {
        let existing_buffer_clone = existing_bytes_buffer.clone();
        memory_manager.mem_copy(
            &mut existing_bytes_buffer[0],
            &mut (address as *mut u8).as_mut().unwrap(),
            existing_buffer_clone.len(),
        );
    }
    let existing_bytes = raw_aob_to_string_aob(existing_bytes_buffer);

    println!("Bytes at address: {}", existing_bytes);
    println!("Expected bytes: {}", expected_bytes);
    println!("New bytes: {}", new_bytes);

    // if check_if_aobs_match(&existing_bytes, expected_bytes) {
    println!("Bytes match");
    let mut raw_new_bytes = string_aob_to_raw_aob(new_bytes).unwrap();
    let raw_new_bytes_clone = raw_new_bytes.clone();
    unsafe {
        memory_manager.mem_copy(
            &mut (address as *mut u8).as_mut().unwrap(),
            &mut raw_new_bytes[0],
            raw_new_bytes_clone.len(),
        );
    }
    println!("Patch applied");
    true
    // } else {
    // false
    // }
}
