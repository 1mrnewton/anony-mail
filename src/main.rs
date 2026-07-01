use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tempmail_backend::run().await
}
