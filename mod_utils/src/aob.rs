use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::shared::minwindef::{HINSTANCE, HMODULE, LPVOID};
use winapi::shared::winerror::ERROR_INVALID_PARAMETER;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS};
use winapi::um::memoryapi::VirtualQuery;
use winapi::um::processthreadsapi::{GetCurrentProcessId, OpenProcess};
use winapi::um::psapi::EnumProcessModules;
use winapi::um::winbase::{LocalAlloc, LocalFree};
use winapi::um::winnt::{
    MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PROCESS_ALL_ACCESS,
};

use crate::mod_utils::show_error_popup;
use std::fmt::{LowerHex, UpperHex};
use std::mem::zeroed;
use std::process;
use std::ptr::copy_nonoverlapping;

static mut MU_AOB_MASK: &str = "?";

pub fn tokenify_aob_string(aob: &str) -> Vec<String> {
    aob.split_whitespace().map(|s| s.to_string()).collect()
}

pub fn is_aob_valid(aob_tokens: &[String]) -> bool {
    let whitelist = "0123456789abcdef?";

    for byte in aob_tokens {
        if byte.len() != 2 && byte != "?" {
            println!("Invalid byte length: {}", byte);
            return false;
        }

        if byte != "?" && byte.chars().any(|c| !whitelist.contains(c)) {
            println!("Invalid byte: {}", byte);
            return false;
        }
    }
    true
}

pub fn verify_aob(aob: &str) -> bool {
    let aob_tokens = tokenify_aob_string(aob);
    println!("Token AOB: {:?}", aob_tokens);
    if !is_aob_valid(&aob_tokens) {
        crate::mod_utils::show_error_popup(format!("AOB is invalid! ({})", aob));
        false
    } else {
        true
    }
}
pub fn verify_aobs(aobs: &[String]) -> bool {
    for aob in aobs {
        if !verify_aob(aob) {
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

pub fn aob_scan(aob: &str) -> Option<usize> {
    let aob_tokens = tokenify_aob_string(aob);

    if !verify_aob(aob) {
        return None;
    }

    let process_id = unsafe { winapi::um::processthreadsapi::GetCurrentProcessId() };
    let process_base_address = get_process_base_address(process_id);

    if process_base_address == 0 {
        eprintln!("Failed to get process base address.");
        return None;
    }

    let mut region_start = process_base_address;
    let mut num_regions_checked = 0;
    let max_regions_to_check = 10000;
    let mut current_address;

    while num_regions_checked < max_regions_to_check {
        let mut memory_info: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
        let result = unsafe {
            VirtualQuery(
                region_start as *mut _,
                &mut memory_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            let error = unsafe { winapi::um::errhandlingapi::GetLastError() };
            if error == winapi::shared::winerror::ERROR_INVALID_PARAMETER {
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

        let is_memory_readable = (protection == winapi::um::winnt::PAGE_EXECUTE_READWRITE
            || protection == winapi::um::winnt::PAGE_READWRITE
            || protection == winapi::um::winnt::PAGE_READONLY
            || protection == winapi::um::winnt::PAGE_WRITECOPY
            || protection == winapi::um::winnt::PAGE_EXECUTE_WRITECOPY)
            && state == winapi::um::winnt::MEM_COMMIT;

        if is_memory_readable {
            println!("Checking region: {:X}", region_start);
            current_address = region_start;
            while current_address < region_end - aob_tokens.len() {
                let mut found = true;
                for (i, token) in aob_tokens.iter().enumerate() {
                    if token == "?" {
                        continue;
                    } else if unsafe { *((current_address as *const u8).add(i)) }
                        != u8::from_str_radix(token, 16).unwrap()
                    {
                        found = false;
                        break;
                    }
                }
                if found {
                    let signature = current_address;
                    println!("Found signature at {:X}", signature);
                    return Some(signature);
                }
                current_address += 1;
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

pub fn string_aob_to_raw_aob(aob: &str) -> Result<Vec<u8>, String> {
    let tokenified_aob = tokenify_aob_string(aob);
    let mut raw_aob = Vec::new();

    for token in tokenified_aob {
        if token == unsafe { MU_AOB_MASK } {
            return Err("Cannot convert AOB with mask to raw AOB".into());
        }

        match u8::from_str_radix(&token, 16) {
            Ok(byte) => raw_aob.push(byte),
            Err(_) => return Err("Invalid hex string".into()),
        }
    }

    Ok(raw_aob)
}

pub fn raw_aob_to_string_aob(raw_aob: Vec<u8>) -> String {
    let mut aob = String::new();
    for byte in raw_aob {
        let string = number_to_hex_string(byte);
        aob.push_str(&format!("{} ", string));
    }
    aob.pop();
    aob
}

pub fn check_if_aobs_match(aob1: &str, aob2: &str) -> bool {
    let aob1_tokens = tokenify_aob_string(aob1);
    let aob2_tokens = tokenify_aob_string(aob2);

    let shortest_aob_length = aob1_tokens.len().min(aob2_tokens.len());
    for i in 0..shortest_aob_length {
        let token_is_masked =
            aob1_tokens[i] == unsafe { MU_AOB_MASK } || aob2_tokens[i] == unsafe { MU_AOB_MASK };
        if token_is_masked {
            continue;
        }

        if aob1_tokens[i] != aob2_tokens[i] {
            show_error_popup(format!("Bytes do not match!"));
            return false;
        }
    }
    true
}

pub fn replace_expected_bytes_at_address(
    address: *mut u8,
    expected_bytes: &str,
    new_bytes: &str,
) -> bool {
    if !verify_aobs(&[expected_bytes.to_string(), new_bytes.to_string()]) {
        return false;
    }

    let expected_bytes_tokens = tokenify_aob_string(expected_bytes);
    let mut existing_bytes_buffer = vec![0u8; expected_bytes_tokens.len()];
    unsafe {
        copy_nonoverlapping(
            address,
            existing_bytes_buffer.as_mut_ptr(),
            existing_bytes_buffer.len(),
        );
    }
    let existing_bytes = raw_aob_to_string_aob(existing_bytes_buffer);

    println!("Bytes at address: {}", &existing_bytes);
    println!("Expected bytes: {}", expected_bytes);
    println!("New bytes: {}", new_bytes);

    if check_if_aobs_match(&existing_bytes, expected_bytes) {
        println!("Bytes match");
        let raw_new_bytes = string_aob_to_raw_aob(new_bytes).unwrap();
        unsafe {
            copy_nonoverlapping(raw_new_bytes.as_ptr(), address, raw_new_bytes.len());
        }
        println!("Patch applied");
        return true;
    }

    false
}
