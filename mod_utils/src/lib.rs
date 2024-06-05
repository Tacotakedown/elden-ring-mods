use std::mem;
use winapi::vc::{vadefs::uintptr_t, vcruntime::size_t};

pub mod aob;
pub mod memory;
pub mod mod_utils;
pub mod timer;
pub mod windows;

pub fn hook(address: uintptr_t, destination: uintptr_t, extra_clearance: Option<size_t>) {
    let mut clearance: size_t = 0;
    if let Some(extra_clearance) = extra_clearance {
        clearance = 14 + extra_clearance
    } else {
        clearance = 14 + 0
    }
}

pub fn relative_to_absolute_address(relative_address_location: usize) -> usize {
    let mut relative_address: i32 =
        unsafe { mem::transmute::<_, i32>(*((relative_address_location) as *const i32)) };

    let absolute_address = relative_address_location as isize + 4 + relative_address as isize;
    absolute_address as usize
}
