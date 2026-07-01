use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    anony_mail::run().await
}
