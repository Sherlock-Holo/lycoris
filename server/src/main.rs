use server::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    server::run().await
}
