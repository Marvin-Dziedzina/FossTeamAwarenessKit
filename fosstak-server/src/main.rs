use fosstak_server::response;

#[macro_use]
extern crate rocket;

#[get("/")]
fn index() -> String {
    response::get_json_result("")
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![index])
}
