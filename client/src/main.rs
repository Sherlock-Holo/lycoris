#[tokio::main]
async fn main() -> anyhow::Result<()> {
    lycoris_client::run().await
}
