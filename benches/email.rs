use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use structured_email_address::{Config, EmailAddress, Strictness};

fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse");

    let cases = [
        ("simple", "user@example.com"),
        ("subaddress", "user+tag@example.com"),
        ("dotted", "first.last@example.com"),
        ("quoted", "\"user name\"@example.com"),
        ("utf8_local", "дмитрий@example.com"),
        ("utf8_domain", "user@münchen.de"),
        (
            "long",
            "very.long.local.part.with.many.dots@subdomain.example.co.uk",
        ),
    ];

    for (name, input) in &cases {
        group.bench_with_input(BenchmarkId::new("default", name), input, |b, input| {
            b.iter(|| black_box(input).parse::<EmailAddress>());
        });
    }

    // Display name requires config
    let config_display = Config::builder().allow_display_name().build();
    group.bench_function("display_name_configured", |b| {
        b.iter(|| {
            EmailAddress::parse_with(black_box("John Doe <user@example.com>"), &config_display)
        });
    });

    group.finish();
}

fn bench_normalize(c: &mut Criterion) {
    let mut group = c.benchmark_group("normalize");

    let gmail_config = Config::builder()
        .strip_subaddress()
        .dots_gmail_only()
        .lowercase_all()
        .build();

    group.bench_function("gmail_full_pipeline", |b| {
        b.iter(|| EmailAddress::parse_with(black_box("A.L.I.C.E+promo@Gmail.COM"), &gmail_config));
    });

    let confusable_config = Config::builder()
        .lowercase_all()
        .check_confusables()
        .build();

    group.bench_function("confusable_check", |b| {
        b.iter(|| EmailAddress::parse_with(black_box("user@example.com"), &confusable_config));
    });

    group.bench_function("idna_domain", |b| {
        b.iter(|| EmailAddress::parse_with(black_box("user@münchen.de"), &gmail_config));
    });

    group.finish();
}

fn bench_strictness(c: &mut Criterion) {
    let mut group = c.benchmark_group("strictness");

    let strict = Config::builder().strictness(Strictness::Strict).build();
    let standard = Config::builder().strictness(Strictness::Standard).build();
    let lax = Config::builder().strictness(Strictness::Lax).build();

    let input = "user@example.com";

    group.bench_function("strict", |b| {
        b.iter(|| EmailAddress::parse_with(black_box(input), &strict));
    });
    group.bench_function("standard", |b| {
        b.iter(|| EmailAddress::parse_with(black_box(input), &standard));
    });
    group.bench_function("lax", |b| {
        b.iter(|| EmailAddress::parse_with(black_box(input), &lax));
    });

    // Mode-sensitive: quoted-string accepted by Standard, rejected by Strict
    group.bench_function("standard_quoted", |b| {
        b.iter(|| EmailAddress::parse_with(black_box("\"user name\"@example.com"), &standard));
    });

    group.finish();
}

fn bench_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch");

    // Build a 100K-element list: mix of valid and invalid addresses
    let valid = [
        "alice@example.com",
        "bob+tag@gmail.com",
        "carol.smith@subdomain.example.co.uk",
        "дмитрий@example.com",
        "user@münchen.de",
        "first.last@company.org",
        "x@y.io",
        "very.long.local.part@test.com",
    ];
    let invalid = ["", "noatsign", "@missing.com", "user@localhost"];

    let mut inputs: Vec<&str> = Vec::with_capacity(100_000);
    let all: Vec<&str> = valid.iter().chain(invalid.iter()).copied().collect();
    for chunk in all.iter().cycle().take(100_000) {
        inputs.push(chunk);
    }

    let config = Config::builder()
        .strip_subaddress()
        .dots_gmail_only()
        .lowercase_all()
        .build();

    // Sequential: parse_batch on 100K emails
    group.bench_function("sequential_100k", |b| {
        b.iter(|| EmailAddress::parse_batch(black_box(&inputs), black_box(&config)));
    });

    // Sequential loop (baseline comparison)
    group.bench_function("loop_100k", |b| {
        b.iter(|| {
            let _results: Vec<_> = inputs
                .iter()
                .map(|input| EmailAddress::parse_with(black_box(input), &config))
                .collect();
        });
    });

    group.finish();
}

#[cfg(feature = "rayon")]
fn bench_batch_par(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_parallel");

    let valid = [
        "alice@example.com",
        "bob+tag@gmail.com",
        "carol.smith@subdomain.example.co.uk",
        "дмитрий@example.com",
        "user@münchen.de",
        "first.last@company.org",
        "x@y.io",
        "very.long.local.part@test.com",
    ];
    let invalid = ["", "noatsign", "@missing.com", "user@localhost"];

    let mut inputs: Vec<&str> = Vec::with_capacity(100_000);
    let all: Vec<&str> = valid.iter().chain(invalid.iter()).copied().collect();
    for chunk in all.iter().cycle().take(100_000) {
        inputs.push(chunk);
    }

    let config = Config::builder()
        .strip_subaddress()
        .dots_gmail_only()
        .lowercase_all()
        .build();

    group.bench_function("parallel_100k", |b| {
        b.iter(|| EmailAddress::parse_batch_par(black_box(&inputs), black_box(&config)));
    });

    group.finish();
}

#[cfg(feature = "rayon")]
criterion_group!(
    benches,
    bench_parse,
    bench_normalize,
    bench_strictness,
    bench_batch,
    bench_batch_par
);
#[cfg(feature = "rayon")]
criterion_main!(benches);

#[cfg(not(feature = "rayon"))]
criterion_group!(
    benches,
    bench_parse,
    bench_normalize,
    bench_strictness,
    bench_batch
);
#[cfg(not(feature = "rayon"))]
criterion_main!(benches);
