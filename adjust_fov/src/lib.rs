use ini::Ini;
use mod_utils::{
    aob::aob_scan,
    hook, memory,
    mod_utils::{find_dll, get_current_mod_name},
    relative_to_absolute_address,
};
use std::arch::asm;
use std::env;
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
static mut Fov: [f32; 4] = [0.0, 0.0, 0.0, 0.0];
#[allow(non_upper_case_globals)]
static mut ReturnAddress: usize = 0;
#[allow(non_upper_case_globals)]
static mut ResolvedRelativeAddress: usize = 0;

fn fov_adjust() {
    for _ in 0..9 {
        unsafe {
            asm!("nop");
        }
    }

    unsafe {
        let call_fn: extern "C" fn() = std::mem::transmute(ResolvedRelativeAddress);
        call_fn();

        let xmm0: [f32; 4] = Fov;
        std::arch::x86_64::_mm_load_ps(xmm0.as_ptr());

        let jmp_fn: extern "C" fn() = std::mem::transmute(ReturnAddress);
        jmp_fn();
    }
}

fn read_config() {
    // let mod_name = get_current_mod_name();
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
    thread::sleep(Duration::from_secs(5));

    let mut memory_manager = memory::MemoryProtection::new();
    println!("Activating AdjustTheFov...");

    let aob = "8d ? ? ? ? 0f 28 ? e8 ? ? ? ? 80 ? ? ? ? ? ? ? 0f 28 ? f3 ? 0f 10 ? ? ? ? ? ? 0f 57 ? f3 ? 0f 59";
    if let Some(hook_address) = aob_scan(aob) {
        let offset = 1;
        let mut hook_address = hook_address - offset;
        println!("hook address: {}", hook_address);
        let size = 9;
        let offset = 0;
        let mut hook_address_u8 = hook_address as u8;

        let fov_adjust_length = get_function_length(fov_adjust as *const () as *const ());

        println!("Length of fov_adjust function: {} bytes", fov_adjust_length);

        read_config();

        hook_address += offset;

        type FnType = fn();
        let fov_adjust_ptr: FnType = fov_adjust;
        let raw_ptr = fov_adjust_ptr as *mut u8;

        let raw_ref: &mut u8 = unsafe { &mut *raw_ptr };

        memory_manager.mem_copy(raw_ref, &mut hook_address_u8, size);
        unsafe {
            ReturnAddress = hook_address + 14;
            ResolvedRelativeAddress =
                relative_to_absolute_address(hook_address + 10, &mut memory_manager);
        }

        let raw_ptr = hook_address as *mut u8;

        let byte_slice: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(raw_ptr, 9) };

        hook(byte_slice, raw_ref, None, &mut memory_manager);
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

fn get_function_length(func_ptr: *const ()) -> usize {
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
    let result = unsafe { VirtualQuery(func_ptr as *const _, &mut mbi, mbi_size) };

    if result == 0 {
        return 0;
    }

    if mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE) == 0 {
        return 0;
    }

    let start_addr = mbi.BaseAddress as usize;
    let end_addr = (mbi.BaseAddress as usize + mbi.RegionSize) as *const u8;

    let func_len = end_addr as usize - func_ptr as usize;
    func_len
}
