use criterion::{black_box, criterion_group, criterion_main, Criterion};
use live_analyzer::features::extract_features;
use live_analyzer::flow::{Direction, Flow, FlowKey};

fn dummy_flow() -> Flow {
    let key = FlowKey::new(
        u32::from(std::net::Ipv4Addr::new(192, 168, 1, 100)),
        50000,
        u32::from(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        443,
    );
    let mut ts = 1000.0;
    let mut flow = Flow::new(key, ts);
    
    // Simulate some packet exchanges.
    for i in 0..100 {
        let dir = if i % 2 == 0 { Direction::Up } else { Direction::Down };
        let size = if i % 3 == 0 { 1500 } else { 100 };

        let payload = vec![0u8; size];
        flow.add_packet(ts, dir, &payload);
        ts += 0.01;
    }
    
    flow
}

fn bench_extract_features(c: &mut Criterion) {
    let flow = dummy_flow();
    c.bench_function("feature_extraction (100 pkts)", |b| {
        b.iter(|| extract_features(black_box(&flow)))
    });
}

criterion_group!(benches, bench_extract_features);
criterion_main!(benches);
