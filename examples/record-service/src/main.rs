//! Run the local synthetic record service at <http://127.0.0.1:3000>.
use gatekeep_example_record_service::{ExampleError, database, router};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), ExampleError> {
    let app = router(database().await?).await?;
    let listener = TcpListener::bind("127.0.0.1:3000").await?;
    println!("Synthetic fixtures: http://127.0.0.1:3000/people/parent/records/one");
    axum::serve(listener, app).await?;
    Ok(())
}
