use elden_ring_utils_rs::bindings;
use ini::Ini;
use std::arch::asm;
use std::env;
use std::path::Path;
use std::thread;
use std::time::Duration;
use winapi::{
    ctypes::c_void,
    um::{
        consoleapi::AllocConsole,
        memoryapi::VirtualQuery,
        winnt::{MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
    },
};
use winapi::{
    shared::minwindef::{HINSTANCE, LPVOID},
    um::{
        libloaderapi::DisableThreadLibraryCalls, processthreadsapi::CreateThread,
        winnt::DLL_PROCESS_ATTACH,
    },
};

#[allow(non_upper_case_globals)]
static mut fov: [f32; 4] = [48.0, 0.0, 0.0, 0.0];
#[allow(non_upper_case_globals)]
static mut return_address: usize = 0;
#[allow(non_upper_case_globals)]
static mut resolved_relative_address: usize = 0;

#[allow(static_mut_refs)]
#[allow(non_snake_case)]
#[allow(unused_variables)]
unsafe fn FovAdjust() {
    asm!(
        "
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        call {resolved_relative_address}
        movaps xmm0, xmmword ptr [{fov}]
        jmp qword ptr [{return_address}]
        ",

        fov = in(reg) &fov,
        resolved_relative_address = in(reg) &resolved_relative_address,
        return_address = in(reg) &return_address,
    );
}

fn read_config() {
    let mod_name = bindings::get_current_mod_name();
    let dll_name = format!("{}.dll", mod_name);

    let base_folder = env::current_dir().unwrap();
    let base_folder = base_folder.to_str().unwrap();

    let dll_path = bindings::find_dll(&base_folder, &dll_name);

    let ini_path = dll_path.replace(".dll", ".ini");
    println!("Loading INI for Fov Adjust from: {}", &ini_path);

    let ini_exists = Path::new(&ini_path).exists();

    if ini_exists {
        let conf = Ini::load_from_file(&ini_path).unwrap();
        let section = conf.section(Some("FOV")).unwrap();
        let fov_from_config = section.get("value").unwrap();

        match fov_from_config.parse::<f32>() {
            Ok(float_value) => unsafe {
                fov[0] = float_value;
                println!("FOV Adjust: Loaded fov of: {} from config", fov[0]);
            },
            Err(_) => {
                eprintln!("FOV Adjust: Failed to parse FOV from INI file, make sure you use a float ie. 90.0");
            }
        }
    } else {
        println!("FOV Adjust: No config file found, creating a new one with default params");

        let mut conf = Ini::new();
        conf.with_section(Some("FOV")).set("value", "48.0");
        conf.write_to_file(&ini_path).unwrap();
    }
}

extern "system" fn main_thread(_lp_param: LPVOID) -> u32 {
    thread::sleep(Duration::from_secs(5));

    println!("Activating Adjust FOV...");

    let aob = "8d ? ? ? ? 0f 28 ? e8 ? ? ? ? 80 ? ? ? ? ? ? ? 0f 28 ? f3 ? 0f 10 ? ? ? ? ? ? 0f 57 ? f3 ? 0f 59";
    let mut hook_address = bindings::aob_scan(aob);
    let offset = 1;

    if hook_address != 0 {
        read_config();
        hook_address += offset;
        let size = 9;
        bindings::mem_copy(FovAdjust as usize, hook_address, size);
        unsafe {
            return_address = bindings::relative_to_absolute_address(hook_address + 10);
        }
        bindings::hook(hook_address, FovAdjust as usize, 0);
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
