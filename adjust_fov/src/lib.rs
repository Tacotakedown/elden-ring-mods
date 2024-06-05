use ini::Ini;
use lazy_static::lazy_static;
use mod_utils::{
    aob::{self, aob_scan},
    memory,
    mod_utils::{find_dll, get_current_mod_name},
    relative_to_absolute_address, timer, windows,
};
use std::arch::asm;
use std::time::Duration;
use std::{borrow::BorrowMut, env};
use std::{default, sync::Mutex};
use std::{process::Command, thread};
use winapi::{ctypes::c_void, um::consoleapi::AllocConsole};
use winapi::{
    shared::minwindef::{HINSTANCE, LPVOID},
    um::{
        libloaderapi::DisableThreadLibraryCalls, minwinbase::LPTHREAD_START_ROUTINE,
        processthreadsapi::CreateThread, winnt::DLL_PROCESS_ATTACH,
    },
};

static mut Fov: [f32; 4] = [0.0, 0.0, 0.0, 0.0];
static mut ReturnAddress: usize = 0;
static mut ResolvedRelativeAddress: usize = 0;

fn fov_adjust() {
    for _ in 0..9 {
        unsafe {
            asm!("nop");
        }
    }

    unsafe {
        // Call the resolved relative address
        let call_fn: extern "C" fn() = std::mem::transmute(ResolvedRelativeAddress);
        call_fn();

        // Move data from `fov` to `xmm0`
        let xmm0: [f32; 4] = Fov;
        std::arch::x86_64::_mm_load_ps(xmm0.as_ptr());

        // Jump to return address
        let jmp_fn: extern "C" fn() = std::mem::transmute(ReturnAddress);
        jmp_fn();
    }
}

fn read_config() {
    let mod_name = get_current_mod_name();
    let dll_name = format!("adjust_fov.dll");

    let base_folder = env::current_exe().unwrap();
    let base_folder = base_folder.parent().unwrap();

    let dll_path = match find_dll(base_folder.to_str().unwrap(), &dll_name) {
        Some(path) => path,
        None => {
            println!("DLL not found");
            return;
        }
    };

    println!("DLL found at: {}", dll_path);

    let ini_path = dll_path.replace(".dll", ".ini");

    let mut config = match Ini::load_from_file(&ini_path) {
        Ok(config) => config,
        Err(_) => Ini::new(),
    };
    let mut config_clone = config.clone();
    let mut default_config_clone = config.clone();

    let section_name = "fov";
    let fov_value;

    {
        let mut section = config.with_section(Some(section_name.to_owned()));
        let mut section_copy = config_clone.with_section(Some(section_name.to_owned()));
        let l_fov_value = section
            .get("value")
            .unwrap_or("100,0.0,0.0,0.0")
            .to_string();

        let values: Vec<f64> = l_fov_value
            .split(',')
            .map(|s| s.trim().parse().unwrap_or(0.0))
            .collect();

        fov_value = if values.len() == 4 {
            (values[0], values[1], values[2], values[3])
        } else {
            (100.0, 0.0, 0.0, 0.0)
        };

        if section_copy.get("value").is_none() {
            drop(l_fov_value);
            let mut section = default_config_clone.with_section(Some(section_name.to_owned()));
            section.set("value", "48.0,0.0,0.0,0.0");
        }
    }

    config.write_to_file(&ini_path).unwrap();

    println!("Field of view: {:?}", fov_value);
}

extern "system" fn main_thread(_lp_param: LPVOID) -> u32 {
    unsafe {
        AllocConsole();
    }
    thread::sleep(Duration::from_secs(5));

    let mut memory_manager = memory::MemoryProtection::new();
    println!("Activating AdjustTheFov...");

    let aob = "8d ? ? ? ? 0f 28 ? e8 ? ? ? ? 80 ? ? ? ? ? ? ? 0f 28 ? f3 ? 0f 10 ? ? ? ? ? ? 0f 57 ? f3 ? 0f 59";
    if let Some(hook_address) = aob_scan(aob) {
        let offset = 1;
        let hook_address = hook_address - offset;
        println!("hook address: {}", hook_address);
        let size = 9;

        read_config();

        let fov_adjust = fov_adjust as usize;
        memory_manager.mem_copy(fov_adjust, hook_address, size);
        unsafe {
            ReturnAddress = hook_address + 14;
            ResolvedRelativeAddress = relative_to_absolute_address(hook_address + 10);
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
