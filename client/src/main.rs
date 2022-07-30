use client::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    client::run().await
}
