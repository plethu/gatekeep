//! Executable regression corpus for caller-owned relation authorization.
use std::error::Error as StdError;
use std::{env, process::ExitCode, result::Result as StdResult};
mod admission;
mod integrity;
mod policy;
mod reconciliation;
mod scenarios;
mod setup;
mod store;

type Result<T> = StdResult<T, Box<dyn StdError + Send + Sync>>;

#[tokio::main]
async fn main() -> ExitCode {
    let result = async {
        let url = env::var("DATABASE_URL")?;
        let consumer = setup::consumer(&url).await?;
        scenarios::run(&consumer).await
    }
    .await;
    if result.is_ok() {
        println!("Caller-owned transaction, retry, expiry, and admission assertions passed.");
        ExitCode::SUCCESS
    } else {
        // Do not expose connection URLs, opaque metadata, or authentication material.
        eprintln!(
            "Relation consumer verification failed; inspect the failing assertion in the isolated fixture."
        );
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    #[tokio::test]
    #[ignore = "requires a dedicated DATABASE_URL fixture"]
    async fn complete_caller_transaction() -> super::Result<()> {
        let consumer = super::setup::consumer(&env::var("DATABASE_URL")?).await?;
        super::scenarios::run(&consumer).await
    }
}
