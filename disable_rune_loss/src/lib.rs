use mod_utils::aob::aob_scan;
use mod_utils::memory::replace_expected_bytes_at_address;
use mod_utils::memory::MemoryProtection;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::HINSTANCE;
use winapi::shared::minwindef::LPVOID;
use winapi::um::libloaderapi::DisableThreadLibraryCalls;
use winapi::um::processthreadsapi::CreateThread;
use winapi::um::winnt::DLL_PROCESS_ATTACH;

extern "system" fn main_thread(_lp_param: LPVOID) -> u32 {
    std::thread::sleep(std::time::Duration::from_secs(5));
    println!("Activating Disable Rune Loss...");
    let mut memory_manager = MemoryProtection::new();
    let aob = "b0 01 ? 8b ? e8 ? ? ? ? ? 8b ? ? ? 32 c0 ? 83 ? 28 c3";
    let expected_bytes = "e8";
    let new_bytes = "90 90 90 90 90";
    let path_address = aob_scan(aob);
    let offset = 5;

    match path_address {
        Some(path_address) => {
            replace_expected_bytes_at_address(
                path_address + offset,
                expected_bytes,
                new_bytes,
                &mut memory_manager,
            );
        }
        None => {
            println!("Path address is invalid");
            return 0;
        }
    }
    0
}

#[no_mangle]
pub extern "system" fn DllMain(hinst_dll: HINSTANCE, fdw_reason: u32, _lp_reserved: LPVOID) -> u32 {
    if fdw_reason == DLL_PROCESS_ATTACH {
        unsafe {
            DisableThreadLibraryCalls(hinst_dll);
            CreateThread(
                std::ptr::null_mut(),
                0,
                Some(main_thread as unsafe extern "system" fn(*mut c_void) -> u32),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            );
        }
    }
    1
}
