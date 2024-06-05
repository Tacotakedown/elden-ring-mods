use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::prelude::*;
use std::os::windows::ffi::OsStringExt;
use std::path::Path;
use std::process;
use std::ptr::null_mut;
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::Duration;
use winapi::shared::minwindef::{DWORD, HINSTANCE, LPARAM, LRESULT, WPARAM};
use winapi::shared::ntdef::HANDLE;
use winapi::shared::windef::HWND;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{
    GetModuleFileNameA, GetModuleFileNameW, GetModuleHandleExA,
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
};
use winapi::um::memoryapi::{VirtualProtect, VirtualQuery};
use winapi::um::minwinbase::LPTR;
use winapi::um::processthreadsapi::{GetCurrentProcessId, OpenProcess};
use winapi::um::psapi::EnumProcessModules;
use winapi::um::winbase::LocalAlloc;
use winapi::um::winbase::LocalFree;
use winapi::um::winnt::{MEMORY_BASIC_INFORMATION, MEM_COMMIT, PROCESS_ALL_ACCESS};
use winapi::um::winuser::MessageBoxW;
use winapi::um::winuser::{
    EnumWindows, FindWindowExA, GetAsyncKeyState, GetForegroundWindow, GetWindowTextA,
    GetWindowThreadProcessId, MB_ICONERROR, MB_OK, MB_SYSTEMMODAL,
};

use crate::windows::to_string_wide;

const MU_AOB_MASK: &str = "?";
const MU_GAME_NAME: &str = "ELDEN RING";
const MU_EXPECTED_WINDOW_NAME: &str = "ELDEN RING™";

const MAX_PATH: usize = 260;

struct ModUtils {
    window_handle: Option<HWND>,
}

pub fn get_module_name(main_process_module: bool) -> String {
    let mut module: winapi::shared::minwindef::HMODULE = std::ptr::null_mut();
    if !main_process_module {
        let dummy_static_var: u8 = 'x' as u8;
        unsafe {
            GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                    | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                &dummy_static_var as *const u8 as *mut _,
                &mut module,
            );
        }
    }

    let mut filename = [0i8; MAX_PATH];
    unsafe {
        GetModuleFileNameA(module, filename.as_mut_ptr(), filename.len() as u32);
    }
    let filename_u8: Vec<u8> = filename.iter().map(|&c| c as u8).collect();

    let module_name = String::from_utf8_lossy(&filename_u8)
        .trim_matches(char::from(0))
        .rsplit_once('\\')
        .map(|(_, name)| name)
        .unwrap_or("")
        .to_string();

    if !main_process_module {
        let ext_pos = module_name.rfind(".dll").unwrap_or(module_name.len());
        module_name[..ext_pos].to_string()
    } else {
        module_name
    }
}

pub fn get_current_process_name() -> String {
    get_module_name(true)
}

pub fn get_current_mod_name() -> String {
    unsafe {
        let mut buf = vec![0u16; 1024];
        let len = GetModuleFileNameW(null_mut(), buf.as_mut_ptr(), buf.len() as u32);
        if len > 0 {
            let os_string = OsString::from_wide(&buf[..len as usize]);
            if let Some(file_name) = os_string.as_os_str().to_str() {
                return file_name.to_owned();
            }
        }
    }
    String::from("NULL")
}

pub fn get_mod_folder_path() -> String {
    format!("mods\\{}", get_current_mod_name())
}

pub fn find_dll(base_folder: &str, dll_name: &str) -> Option<String> {
    let base_folder = Path::new(base_folder);

    if let Ok(entries) = base_folder.read_dir() {
        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_file() && path.file_name().unwrap() == std::ffi::OsStr::new(dll_name) {
                    return Some(path.to_string_lossy().to_string());
                } else if path.is_dir() {
                    if let Ok(sub_entries) = path.read_dir() {
                        for sub_entry in sub_entries {
                            if let Ok(sub_entry) = sub_entry {
                                let sub_path = sub_entry.path();
                                if sub_path.is_file()
                                    && sub_path.file_name().unwrap()
                                        == std::ffi::OsStr::new(dll_name)
                                {
                                    return Some(sub_path.to_string_lossy().to_string());
                                }
                            }
                        }
                    }
                    if let Some(sub_path) = find_dll(path.to_str().unwrap(), dll_name) {
                        return Some(sub_path);
                    }
                }
            }
        }
    }

    None
}

pub fn show_error_popup(error: String) {
    let error_wide = to_string_wide(&error);
    let mod_name_wide = to_string_wide(&get_current_mod_name());

    println!("Error Popup constructed for: {}", error);
    unsafe {
        MessageBoxW(
            null_mut(),
            error_wide.as_ptr(),
            mod_name_wide.as_ptr(),
            MB_OK | MB_ICONERROR | MB_SYSTEMMODAL,
        );
    }
}

pub fn get_base_address(process_id: u32) -> Option<usize> {
    let mut base_address: usize = 0;
    unsafe {
        let process_handle: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, 0, process_id);
        if !process_handle.is_null() {
            let mut bytes_required: u32 = 0;
            if EnumProcessModules(process_handle, null_mut(), 0, &mut bytes_required) != 0 {
                if bytes_required != 0 {
                    let module_array_bytes = LocalAlloc(LPTR, bytes_required as usize) as *mut u8;
                    if !module_array_bytes.is_null() {
                        let module_array =
                            module_array_bytes as *mut winapi::shared::minwindef::HMODULE;
                        if EnumProcessModules(
                            process_handle,
                            module_array,
                            bytes_required,
                            &mut bytes_required,
                        ) != 0
                        {
                            base_address = *module_array as usize;
                        }
                        LocalFree(module_array_bytes as *mut _);
                    }
                }
            }
            CloseHandle(process_handle);
        }
    }

    if base_address != 0 {
        Some(base_address)
    } else {
        None
    }
}
