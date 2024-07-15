use elden_ring_utils_rs::bindings;
use elden_ring_utils_rs::bindings::replace_expected_bytes_at_address;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::HINSTANCE;
use winapi::shared::minwindef::LPVOID;
use winapi::um::libloaderapi::DisableThreadLibraryCalls;
use winapi::um::processthreadsapi::CreateThread;
use winapi::um::winnt::DLL_PROCESS_ATTACH;

/*
 aob ="80 ? ? ? ? ? ? 48 ? ? ? ? 48 ? ? ? ? ? ? ? ? 49 ? ? ? ? ? 44 ? ? ? ? 48 ? ? ? ? ? ? ? ? ? ? ? E8 ? ? ? ? 48";
 expectedBytes = "80 79 36 00 0F 95 C0";
 patch = "C6 41 36 00 B0 00 90";
*/

extern "system" fn main_thread(_lp_param: LPVOID) -> u32 {
    std::thread::sleep(std::time::Duration::from_secs(5));
    println!("Activating Ride Anywhere");
    let aob = "80 ? ? ? ? ? ? 48 ? ? ? ? 48 ? ? ? ? ? ? ? ? 40 ? ? ? ? ? 44 ? ? ? ? ? ? ? 48 ? ? ? ? ? ? ? ? e8 ? ? ? ? 48";
    //let expected_bytes = "80 79 36 00 0f 95 c0";
    let new_bytes = "c6 41 36 00 b0 00 90";
    let path_address = bindings::aob_scan(aob);
    let offset = 0;

    if path_address != 0 {
        replace_expected_bytes_at_address(path_address + offset, aob, new_bytes);
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
