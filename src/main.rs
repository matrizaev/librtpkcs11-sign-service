mod librtpkcs11;

use std::ffi::CString;

use librtpkcs11::{perform_signing, TMemoryPointer};

fn main() {
    let input = CString::new("Hello World").expect("can't create a cstring");
    let user_pin = CString::new("12345678").expect("can't create a cstring");
    let key_pair_id = CString::new("12345678").expect("can't create a cstring");
    let memory_pointer: TMemoryPointer = TMemoryPointer {
        data: input.into_raw(),
        length: 11,
    };
    unsafe {
        let memory_pointer =
            perform_signing(memory_pointer, user_pin.into_raw(), key_pair_id.into_raw());
        if memory_pointer.length > 0 && !memory_pointer.data.is_null() {
            println!("{}", memory_pointer.length);
            // libc::free(memory_pointer.data as *mut libc::c_void);
        } else {
            println!("perform_signing error");
        }
    }
}
