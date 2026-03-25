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
        ("display_name", "John Doe <user@example.com>"),
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

    group.finish();
}

criterion_group!(benches, bench_parse, bench_normalize, bench_strictness);
criterion_main!(benches);
