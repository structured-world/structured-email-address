//! Print the TypeScript confusables table. The TypeScript build runs this and
//! writes the result to `npm/ts/generated/confusables-data.ts`; it is never
//! committed.
//!
//! UTS #39 computes a skeleton as NFD, then each character replaced by its
//! prototype, then NFD again. Only characters that survive NFD are ever looked
//! up, and for each of those the prototype the TypeScript port needs is exactly
//! the skeleton of that character alone. So the table is generated from the
//! crate's own `skeleton` rather than from a separate copy of the Unicode data,
//! which is what keeps the two implementations on one version of it.

use std::fmt::Write as _;
use std::io::{self, Write as _};

use unicode_normalization::UnicodeNormalization;
use unicode_security::confusable_detection::skeleton;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut table = String::new();
    let mut entries = 0_usize;
    for ch in (0..=0x10FFFF_u32).filter_map(char::from_u32) {
        let single = ch.to_string();
        if !single.nfd().eq(core::iter::once(ch)) {
            continue;
        }
        let prototype: String = skeleton(&single).collect();
        if prototype == single {
            continue;
        }
        // `source:target target ...`, code points in hex, entries joined by `,`.
        if entries > 0 {
            table.push(',');
        }
        write!(table, "{:x}:", u32::from(ch))?;
        for (i, target) in prototype.chars().enumerate() {
            if i > 0 {
                table.push(' ');
            }
            write!(table, "{:x}", u32::from(target))?;
        }
        entries += 1;
    }

    let mut out = io::stdout().lock();
    writeln!(
        out,
        "// Generated at build time by bindings/wasm/examples/confusables.rs from the"
    )?;
    writeln!(out, "// unicode-security tables the Rust crate uses.")?;
    writeln!(
        out,
        "// {entries} entries: `source:target target ...` in hex, joined by `,`."
    )?;
    writeln!(out, "export const CONFUSABLES = \"{table}\";")?;
    Ok(())
}
