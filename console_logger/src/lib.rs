use winapi::ctypes::c_void;
use winapi::shared::minwindef::HINSTANCE;
use winapi::shared::minwindef::LPVOID;
use winapi::um::consoleapi::AllocConsole;
use winapi::um::libloaderapi::DisableThreadLibraryCalls;
use winapi::um::processthreadsapi::CreateThread;
use winapi::um::winnt::DLL_PROCESS_ATTACH;

extern "system" fn main_thread(_lp_param: LPVOID) -> u32 {
    unsafe {
        AllocConsole();
    }
    println!("Console active");
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
