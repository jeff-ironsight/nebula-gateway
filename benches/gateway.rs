use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use nebula::gateway::handler::subscribe_to_channel;
use nebula::{
    gateway::handler::broadcast_message_to_channel,
    protocol::GatewayPayload,
    state::AppState,
    types::{ChannelId, ConnectionId, Token, UserId},
};
use serde_json::{from_str, to_string};
use sqlx::postgres::PgPoolOptions;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::unbounded_channel;
use uuid::Uuid;

fn bench_payload_serde(c: &mut Criterion) {
    let identify = GatewayPayload::Identify {
        token: Token("bench-token".to_string()),
    };
    let identify_text = to_string(&identify).expect("serialize identify payload");

    let mut group = c.benchmark_group("gateway_payload");
    group.bench_function(BenchmarkId::new("serialize", "identify"), |b| {
        b.iter(|| {
            let _ = to_string(black_box(&identify)).expect("serialize identify payload");
        });
    });
    group.bench_function(BenchmarkId::new("deserialize", "identify"), |b| {
        b.iter(|| {
            let _: GatewayPayload =
                from_str(black_box(&identify_text)).expect("deserialize identify payload");
        });
    });
    group.finish();
}

fn bench_broadcast_message(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("create tokio runtime");

    // Note: This benchmark requires a running PostgreSQL for message persistence.
    // Without a DB, the broadcast will fail silently and skip broadcasting.
    let (state, channel_id, author_id, mut receivers) = runtime.block_on(async {
        let db = PgPoolOptions::new()
            .connect_lazy("postgres://postgres:postgres@127.0.0.1/postgres")
            .expect("create lazy pool");
        let state = Arc::new(AppState::new(db, None));

        let channel_id = ChannelId::from(Uuid::new_v4());
        let author_id = UserId::from(Uuid::new_v4());

        let mut receivers = Vec::new();
        for _ in 0..100 {
            let (tx, rx) = unbounded_channel();
            let connection_id = ConnectionId::from(Uuid::new_v4());
            state.connections.insert(connection_id, tx);
            subscribe_to_channel(&state, channel_id, connection_id);
            receivers.push(rx);
        }

        (state, channel_id, author_id, receivers)
    });

    c.bench_function("broadcast_message/100_members", |b| {
        b.iter(|| {
            runtime.block_on(broadcast_message_to_channel(
                black_box(&state),
                black_box(&channel_id),
                black_box(&author_id),
                black_box("bench-user"),
                black_box("hello benchmark"),
            ));
            for rx in receivers.iter_mut() {
                while rx.try_recv().is_ok() {}
            }
        });
    });

    drop(receivers);
    drop(state);
    runtime.shutdown_timeout(Duration::from_secs(1));
}

criterion_group!(benches, bench_payload_serde, bench_broadcast_message);
criterion_main!(benches);
