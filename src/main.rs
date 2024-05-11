mod librtpkcs11sign;

use librtpkcs11sign::{rtpkcs11sign_get_slots_info, rtpkcs11sign_perform_signing};

use actix_web::{get, middleware::Logger, post, App, HttpServer, Responder};
use actix_web::{web, Result};
use serde::{Deserialize, Serialize};

#[get("/")]
async fn slots() -> Result<impl Responder> {
    let obj = rtpkcs11sign_get_slots_info();
    match obj {
        Some(val) => Ok(web::Json(val)),
        None => Err(actix_web::error::ErrorInternalServerError("No slots found")),
    }
}

#[derive(Deserialize)]
struct SignRequest {
    slot_id: usize,
    user_pin: String,
    key_pair_id: String,
    data: Vec<u8>,
}

#[derive(Serialize)]
struct SignResponse {
    signature: Vec<u8>,
}

#[post("/sign")]
async fn sign(req_body: web::Json<SignRequest>) -> Result<impl Responder> {
    let obj = rtpkcs11sign_perform_signing(
        req_body.data.clone(),
        &req_body.user_pin,
        &req_body.key_pair_id,
        req_body.slot_id,
    );
    match obj {
        Some(val) => Ok(web::Json(SignResponse { signature: val })),
        None => Err(actix_web::error::ErrorInternalServerError(
            "Couldn't generate signature",
        )),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    HttpServer::new(|| {
        App::new()
            .service(slots)
            .service(sign)
            .wrap(Logger::default())
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
