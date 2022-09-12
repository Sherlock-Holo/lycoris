use lycoris_server::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    lycoris_server::run().await
}
