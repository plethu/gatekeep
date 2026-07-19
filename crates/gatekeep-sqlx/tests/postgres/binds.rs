use sqlx::{
    Postgres, QueryBuilder,
    types::{
        Uuid,
        time::{Date, PrimitiveDateTime, Time},
    },
};

use crate::support::{TestError, TestResult, pool, push_typed_bind};

#[tokio::test]
#[ignore = "requires docker postgres; run `mise exec -- just test-db-postgres`"]
async fn common_postgres_bind_values_round_trip() -> TestResult<()> {
    let pool = pool().await?;
    let uuid = Uuid::from_u128(0x123e_4567_e89b_12d3_a456_4266_1417_4000);
    let date = Date::from_ordinal_date(2026, 171).map_err(|_| TestError::InvalidTemporalValue)?;
    let time = Time::from_hms(14, 30, 15).map_err(|_| TestError::InvalidTemporalValue)?;
    let timestamp = PrimitiveDateTime::new(date, time);
    let timestamptz = timestamp.assume_utc();
    let bytes = vec![1, 2, 3, 4];
    let mut query = QueryBuilder::<Postgres>::new("SELECT ");

    push_typed_bind(&mut query, true, "boolean", false);
    push_typed_bind(&mut query, 7_i16, "smallint", true);
    push_typed_bind(&mut query, 42_i32, "integer", true);
    push_typed_bind(&mut query, 99_i64, "bigint", true);
    push_typed_bind(&mut query, "owner", "text", true);
    push_typed_bind(&mut query, bytes.clone(), "bytea", true);
    push_typed_bind(&mut query, uuid, "uuid", true);
    push_typed_bind(&mut query, date, "date", true);
    push_typed_bind(&mut query, time, "time", true);
    push_typed_bind(&mut query, timestamp, "timestamp", true);
    push_typed_bind(&mut query, timestamptz, "timestamptz", true);

    let row = query
        .build_query_as::<(
            bool,
            i16,
            i32,
            i64,
            String,
            Vec<u8>,
            Uuid,
            Date,
            Time,
            PrimitiveDateTime,
            sqlx::types::time::OffsetDateTime,
        )>()
        .fetch_one(&pool)
        .await?;

    assert_eq!(
        row,
        (
            true,
            7,
            42,
            99,
            "owner".to_owned(),
            bytes,
            uuid,
            date,
            time,
            timestamp,
            timestamptz,
        )
    );
    Ok(())
}
