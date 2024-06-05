use memory::MemoryProtection;
use std::mem;
use winapi::vc::{vadefs::uintptr_t, vcruntime::size_t};

pub mod aob;
pub mod memory;
pub mod mod_utils;
pub mod timer;
pub mod windows;

pub fn hook(
    address: &mut [u8],
    destination: usize,
    extra_clearance: Option<usize>,
    memory_manager: &mut MemoryProtection,
) {
    let clearance = 14 + extra_clearance.unwrap_or(0);

    memory_manager.mem_set(&mut address[0], 0x90, clearance); // nop everything first then we will patch

    let jump_instruction: u64 = 0x0000000025FF;
    let jump_bytes = jump_instruction.to_le_bytes();
    address[..std::mem::size_of::<u64>()].copy_from_slice(&jump_bytes);

    let destination_bytes = (destination as u64).to_le_bytes();
    memory_manager.mem_copy(&mut address[6], &destination_bytes[0], 8);

    println!(
        "Created jump from {:#X} to {:#X} with a clearance of {}",
        address.as_ptr() as usize,
        destination,
        clearance
    );
}

pub fn relative_to_absolute_address(
    relative_address_location: usize,
    memory_manager: &mut MemoryProtection,
) -> usize {
    let mut relative_address: i32 = 0;

    let relative_address_bytes: &mut [u8; 4] = unsafe {
        std::slice::from_raw_parts_mut(&mut relative_address as *mut i32 as *mut u8, 4)
            .try_into()
            .unwrap()
    };

    let relative_address_location_ptr = relative_address_location as *const u8;
    memory_manager.mem_copy(
        &mut relative_address_bytes[0],
        unsafe { &*relative_address_location_ptr },
        4,
    );

    let absolute_address = relative_address_location as isize + 4 + relative_address as isize;

    absolute_address as usize
}
