use winapi::shared::minwindef::{HINSTANCE, HMODULE, LPVOID};
use winapi::shared::winerror::ERROR_INVALID_PARAMETER;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS};
use winapi::um::memoryapi::VirtualQuery;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::EnumProcessModules;
use winapi::um::winbase::{LocalAlloc, LocalFree};
use winapi::um::winnt::{
    MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PROCESS_ALL_ACCESS,
};

use crate::logger::Logger;
use std::fmt::{LowerHex, UpperHex};
use std::process;
use std::str::FromStr;

static mut MU_AOB_MASK: &str = "?";

pub fn tokenify_aob_string(aob: &str) -> Vec<String> {
    aob.split_whitespace()
        .map(|s| String::from_str(s).unwrap())
        .collect()
}

pub fn is_aob_valid(aob_tokens: &[String]) -> bool {
    let whitelist = "0123456789abcdef";

    for byte in aob_tokens {
        if byte.len() != 2 {
            return false;
        }

        if byte.chars().any(|c| !whitelist.contains(c)) {
            return false;
        }
    }
    true
}

pub fn verify_aob(aob: &str, logger: &mut Logger) -> bool {
    let aob_tokens = tokenify_aob_string(aob);
    if !is_aob_valid(&aob_tokens) {
        crate::mod_utils::show_error_popup(format!("AOB is invalid! ({})", aob), logger);
        false
    } else {
        true
    }
}

pub fn verify_aobs(aobs: &[String], logger: &mut Logger) -> bool {
    for aob in aobs {
        if !verify_aob(aob, logger) {
            return false;
        }
    }
    true
}

fn number_to_hex_string<T: LowerHex + UpperHex>(number: T) -> String {
    format!("{:02X}", number)
}

fn number_to_hex_string_unsigned_char(number: u8) -> String {
    format!("{:02X}", number)
}

fn get_process_base_address(process_id: u32) -> usize {
    unsafe {
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id);

        if process_handle.is_null() {
            return 0;
        }

        let mut bytes_required: u32 = 0;
        if EnumProcessModules(process_handle, std::ptr::null_mut(), 0, &mut bytes_required) == 0 {
            CloseHandle(process_handle);
            return 0;
        }

        let module_array_bytes = LocalAlloc(0, bytes_required as usize);

        if module_array_bytes.is_null() {
            CloseHandle(process_handle);
            return 0;
        }

        let mut module_array: Vec<HMODULE> = std::slice::from_raw_parts_mut(
            module_array_bytes as *mut HMODULE,
            bytes_required as usize / std::mem::size_of::<HMODULE>(),
        )
        .to_vec();

        if EnumProcessModules(
            process_handle,
            module_array.as_mut_ptr(),
            bytes_required,
            &mut bytes_required,
        ) == 0
        {
            LocalFree(module_array_bytes as LPVOID);
            CloseHandle(process_handle);
            return 0;
        }

        let base_address = module_array[0] as usize;
        LocalFree(module_array_bytes as LPVOID);
        CloseHandle(process_handle);
        base_address
    }
}

pub fn aob_scan(aob: &str, logger: &mut Logger) -> Option<usize> {
    let aob_tokens = tokenify_aob_string(aob);

    if !verify_aob(aob, logger) {
        return None;
    }

    let process_id = process::id();
    let process_exe = std::env::current_exe().unwrap();
    let file_name = process_exe.file_name().unwrap().to_str().unwrap();
    let process_base_address = get_process_base_address(process_id);

    let mut region_start = process_base_address;
    let mut num_regions_checked = 0;
    let max_regions_to_check = 10000;
    let mut current_address;

    while num_regions_checked < max_regions_to_check {
        let mut memory_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe {
            VirtualQuery(
                region_start as *mut _,
                &mut memory_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>() as _,
            )
        } == 0
        {
            let error = std::io::Error::last_os_error().raw_os_error().unwrap();
            if error == ERROR_INVALID_PARAMETER as i32 {
                println!("Reached end of scannable memory.");
            } else {
                println!("VirtualQuery failed, error code: {}", error);
            }
            break;
        }

        region_start = memory_info.BaseAddress as usize;
        let region_size = memory_info.RegionSize as usize;
        let region_end = region_start + region_size;
        let protection = memory_info.Protect as u32;
        let state = memory_info.State as u32;

        let is_memory_readable = (protection == PAGE_EXECUTE_READWRITE
            || protection == PAGE_READWRITE
            || protection == PAGE_READONLY
            || protection == PAGE_WRITECOPY
            || protection == PAGE_EXECUTE_WRITECOPY)
            && state == MEM_COMMIT;

        if is_memory_readable {
            current_address = region_start;
            while current_address < region_end - aob_tokens.len() {
                let mut found = true;
                for (i, token) in aob_tokens.iter().enumerate() {
                    if unsafe { token == MU_AOB_MASK } {
                        current_address += 1;
                        continue;
                    } else if unsafe { *((current_address as *const u8).offset(i as isize)) }
                        != u8::from_str_radix(token, 16).unwrap()
                    {
                        current_address += 1;
                        found = false;
                        break;
                    }
                }
                if found {
                    let signature = current_address - aob_tokens.len() + 1;
                    return Some(signature);
                }
            }
        } else {
            println!("Skipped region: {:X}", region_start);
        }

        num_regions_checked += 1;
        region_start += region_size;
    }

    println!("Could not find signature!");
    None
}
