use lycoris_client::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    lycoris_client::run().await
}
