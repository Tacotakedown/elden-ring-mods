use elden_ring_utils_rs::bindings;
use ini::Ini;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::Path;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::HINSTANCE;
use winapi::shared::minwindef::LPVOID;
use winapi::um::consoleapi::AllocConsole;
use winapi::um::libloaderapi::DisableThreadLibraryCalls;
use winapi::um::processthreadsapi::CreateThread;
use winapi::um::winnt::DLL_PROCESS_ATTACH;

#[derive(Debug, Deserialize, Serialize)]
struct Config {
    pub disable_camera_auto_rotate: Option<bool>,
    pub disable_camera_reset: Option<bool>,
}

fn read_config() -> Config {
    let mod_name = bindings::get_current_mod_name();
    let dll_name = format!("{}.dll", mod_name);

    let base_folder = env::current_dir().unwrap();
    let base_folder = base_folder.to_str().unwrap();

    let dll_path = bindings::find_dll(&base_folder, &dll_name);

    let ini_path = dll_path.replace(".dll", ".ini");
    println!("Loading INI for Camera Fix from: {}", &ini_path);

    let mut config = Config {
        disable_camera_auto_rotate: None,
        disable_camera_reset: None,
    };

    let ini_exists = Path::new(&ini_path).exists();

    if ini_exists {
        let conf = Ini::load_from_file(&ini_path).unwrap();

        let section = conf.section(Some("Camera Fix")).unwrap();
        let camera_auto_rotate = section.get("disable_camera_auto_rotate").unwrap();
        let camera_reset = section.get("disable_camera_reset").unwrap();

        if camera_auto_rotate == "1" {
            config.disable_camera_auto_rotate = Some(true);
        } else {
            config.disable_camera_auto_rotate = Some(false);
        }

        if camera_reset == "1" {
            config.disable_camera_reset = Some(true);
        } else {
            config.disable_camera_reset = Some(false);
        }

        println!("Camera Fix: Loaded config: {:?}", config);
    } else {
        println!("Camera Fix: No config file found, creating a new one with default params");

        let mut conf = Ini::new();
        conf.with_section(Some("Camera Fix"))
            .set("disable_camera_auto_rotate", "1")
            .set("disable_camera_reset", "1");

        conf.write_to_file(&ini_path).unwrap();
    }

    config
}

extern "system" fn main_thread(_lp_param: LPVOID) -> u32 {
    println!("Activating Camera Fix...");

    let config = read_config();

    match config.disable_camera_auto_rotate {
        Some(auto_rotate) => {
            if auto_rotate {
                let aob = "0f 29 ? ? ? ? ? ? 0f 28 ? ? 8b ? e8 ? ? ? ? ? 0f b6 ? ? ? ? 0f 28 ? ? 8b ? e8 ? ? ? ? ? 8b ? ? 0f 28 ? ? 8b ? e8 ? ? ? ? ? 8d ? ? ? 8b ? ? 8d";
                let new_bytes = "90 90 90 90 90 90 90";
                let patch_address = bindings::aob_scan(aob);
                if patch_address != 0 {
                    bindings::replace_expected_bytes_at_address(patch_address, &aob, &new_bytes);
                }
                println!("Camera Fix: Disabled camera auto rotate");
            }
        }
        None => {
            println!("Camera Fix: Failed to parse config results")
        }
    }

    match config.disable_camera_reset {
        Some(cam_reset) => {
            if cam_reset {
                let aob = "80 ? ? ? ? ? 00 74 ? ? 8b ? e8 ? ? ? ? eb ? 0f 28 ? ? ? ? ? ? 8d";
                let expected_bytes = "74";
                let new_bytes = "eb";
                let mut patch_address = bindings::aob_scan(aob);
                let offset = 7;
                if patch_address != 0 {
                    patch_address += offset;
                    bindings::replace_expected_bytes_at_address(
                        patch_address,
                        &expected_bytes,
                        &new_bytes,
                    );
                }
                println!("Camera Fix: Disabled camera reset");
            }
        }
        None => {
            println!("Camera Fix: Failed to parse config results")
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
