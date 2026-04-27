//! Short, human-typable identifiers for ephemeral approval flows.
//!
//! Used by Hermod's permission-relay (Claude Code Channels permission
//! requests forwarded to a remote operator). The ID has to be:
//!
//! * **Short enough to type on a phone** — five characters.
//! * **Unambiguous in handwriting / autocorrect** — lowercase, no `l`
//!   (could read as `1` or `I`), no digits.
//! * **Drawn from a fixed alphabet a regex can pin** — the operator's
//!   reply ("yes <id>" / "no <id>") is parsed by `^\s*(y|yes|n|no)\s+
//!   ([a-km-z]{5})\s*$/i`. Anything outside the alphabet falls through
//!   as ordinary chat.
//!
//! With 25 letters and length 5, the space is `25^5 = 9_765_625`.
//! Approval requests live for a few minutes at most, so collision
//! probability across the live set is negligible.

use rand::Rng;

/// Permitted characters: lowercase a..z minus `l`. Length 25.
pub const ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyz";

/// Number of characters in a short id.
pub const LEN: usize = 5;

/// Total identifier space: `ALPHABET.len()^LEN`.
pub const SPACE: u64 = 9_765_625; // 25^5

/// Generate a fresh short id using the supplied RNG.
///
/// Use this with `rand::thread_rng()` for production calls; deterministic
/// RNGs are fine for tests.
pub fn generate<R: Rng + ?Sized>(rng: &mut R) -> String {
    let mut out = String::with_capacity(LEN);
    for _ in 0..LEN {
        let i = rng.gen_range(0..ALPHABET.len());
        out.push(ALPHABET[i] as char);
    }
    out
}

/// Validate that `s` matches the short-id grammar exactly: `LEN` lowercase
/// characters, all drawn from `ALPHABET`. Used by the permission-respond
/// RPC to reject malformed verdicts before any state lookup.
pub fn is_valid(s: &str) -> bool {
    if s.len() != LEN {
        return false;
    }
    s.bytes().all(|b| ALPHABET.contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn alphabet_excludes_l_and_uppercase_and_digits() {
        for &b in ALPHABET {
            assert!(b.is_ascii_lowercase(), "non-lowercase byte in alphabet: {b}");
            assert_ne!(b, b'l', "alphabet must exclude `l`");
        }
        // Sanity on the documented size.
        assert_eq!(ALPHABET.len(), 25);
    }

    #[test]
    fn generate_always_in_alphabet() {
        let mut rng = StdRng::seed_from_u64(0xdeadbeef);
        for _ in 0..10_000 {
            let id = generate(&mut rng);
            assert_eq!(id.len(), LEN);
            assert!(is_valid(&id), "generated id failed is_valid: {id}");
            assert!(!id.contains('l'), "generated id contains forbidden `l`: {id}");
        }
    }

    #[test]
    fn is_valid_rejects_obvious_bad_inputs() {
        assert!(!is_valid(""));
        assert!(!is_valid("abcd"));      // too short
        assert!(!is_valid("abcdef"));    // too long
        assert!(!is_valid("abcde\n"));   // wrong length + non-alpha
        assert!(!is_valid("abcdL"));     // uppercase
        assert!(!is_valid("ab1de"));     // digit
        assert!(!is_valid("ablde"));     // contains forbidden `l`
    }

    #[test]
    fn space_constant_matches_alphabet_pow_len() {
        let expected = (ALPHABET.len() as u64).pow(LEN as u32);
        assert_eq!(SPACE, expected);
    }

    /// Sanity collision check: at 1 000 generations the expected number of
    /// collisions in a 5M-id space is well under one. Pinning this catches
    /// a regression to a smaller alphabet or shorter length.
    #[test]
    fn no_obvious_collisions_in_small_sample() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1_000 {
            assert!(seen.insert(generate(&mut rng)), "collision in 1k draws");
        }
    }
}
