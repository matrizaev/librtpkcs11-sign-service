mod librtpkcs11sign;

// use std::ffi::CString;

use librtpkcs11sign::rtpkcs11sign_get_slots_info;

use actix_web::{get, middleware::Logger, post, App, HttpResponse, HttpServer, Responder};
use actix_web::{web, Result};

#[get("/")]
async fn hello() -> Result<impl Responder> {
    let obj = rtpkcs11sign_get_slots_info();
    match obj {
        Some(val) => Ok(web::Json(val)),
        None => Err(actix_web::error::ErrorInternalServerError("No slots found")),
    }
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

// fn sign() {
//     let input = CString::new("Hello World").expect("can't create a cstring");
//     let user_pin = CString::new("12345678").expect("can't create a cstring");
//     let key_pair_id = CString::new("12345678").expect("can't create a cstring");
//     let memory_pointer: TByteArray = TByteArray {
//         data: input.into_raw() as *mut u8,
//         length: 11,
//     };
//     unsafe {
//         let memory_pointer =
//             perform_signing(memory_pointer, user_pin.into_raw(), key_pair_id.into_raw());
//         if memory_pointer.length > 0 && !memory_pointer.data.is_null() {
//             println!("{}", memory_pointer.length);
//             libc::free(memory_pointer.data as *mut libc::c_void);
//         } else {
//             println!("perform_signing error");
//         }
//     }
// }

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    HttpServer::new(|| {
        App::new()
            .service(hello)
            .service(echo)
            .wrap(Logger::default())
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
