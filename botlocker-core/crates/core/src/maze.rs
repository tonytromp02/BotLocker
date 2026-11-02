//! Deterministic, endless maze pages.
//!
//! The page for a path is derived from `HMAC(secret, path)`, so the same path
//! always renders the same page and nothing needs to be stored. Every link is
//! built from the current path, so the maze never leaves its own subtree.

use crate::challenge::keyed_digest;
use crate::CHALLENGE_PATH;

const WORDS: &[&str] = &[
    "archive", "ledger", "harbor", "lantern", "meadow", "circuit", "orchard", "compass", "parcel",
    "signal", "atlas", "quarry", "bramble", "cinder", "drift", "engine", "fable", "garden",
    "hollow", "ivory", "juniper", "kettle", "lumen", "marble", "nectar", "oracle", "pebble",
    "quill", "riddle", "sparrow", "timber", "umber", "velvet", "willow", "yarn", "zephyr",
    "anchor", "beacon", "canyon", "delta",
];

struct Rng(u64);

impl Rng {
    /// SplitMix64.
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn word(&mut self) -> &'static str {
        WORDS[self.below(WORDS.len())]
    }
}

/// Renders the maze page for `path`, truncated to `max_bytes`.
pub fn render(secret: &[u8], path: &str, max_bytes: usize) -> String {
    let digest = keyed_digest(secret, path);
    let mut rng = Rng(u64::from_be_bytes(digest[..8].try_into().expect("8 bytes")));

    let base = html_escape(path.trim_end_matches('/'));
    let title = capitalize(rng.word());

    let mut out = String::new();
    out.push_str("<!doctype html>\n<html><head><meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"robots\" content=\"noindex,nofollow\">\n");
    out.push_str(&format!("<title>{title}</title></head>\n<body>\n<main>\n"));
    out.push_str(&format!("<h1>{title} {}</h1>\n", capitalize(rng.word())));

    for _ in 0..3 + rng.below(3) {
        out.push_str("<p>");
        for _ in 0..3 + rng.below(4) {
            out.push_str(&sentence(&mut rng));
            out.push(' ');
        }
        out.push_str("</p>\n");
    }

    out.push_str("<nav><ul>\n");
    for _ in 0..4 + rng.below(5) {
        let slug = format!("{}-{:06x}", rng.word(), rng.next_u64() & 0xff_ffff);
        let label = format!("{} {}", capitalize(rng.word()), capitalize(rng.word()));
        out.push_str(&format!(
            "<li><a href=\"{base}/{slug}\" rel=\"nofollow\">{label}</a></li>\n"
        ));
    }
    out.push_str("</ul></nav>\n");

    // Escape hatch for a human who landed here by mistake. Bots without JS
    // never receive the pass cookie, so following this link gets them nowhere.
    out.push_str(&format!(
        "<footer><p><a href=\"{CHALLENGE_PATH}?next=/\">Not a bot? Verify here.</a></p></footer>\n"
    ));
    out.push_str("</main>\n</body></html>\n");

    let mut end = out.len().min(max_bytes);
    while !out.is_char_boundary(end) {
        end -= 1;
    }
    out.truncate(end);
    out
}

fn sentence(rng: &mut Rng) -> String {
    let n = 5 + rng.below(5);
    let words: Vec<&str> = (0..n).map(|_| rng.word()).collect();
    format!("{}.", capitalize(&words.join(" ")))
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn html_escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn hrefs(html: &str) -> Vec<String> {
        html.split("href=\"")
            .skip(1)
            .filter_map(|s| s.split('"').next())
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn same_path_renders_identically() {
        assert_eq!(
            render(SECRET, "/maze/a/b", 65536),
            render(SECRET, "/maze/a/b", 65536)
        );
    }

    #[test]
    fn different_paths_render_differently() {
        assert_ne!(
            render(SECRET, "/maze/a", 65536),
            render(SECRET, "/maze/b", 65536)
        );
    }

    #[test]
    fn links_stay_inside_the_current_subtree() {
        let html = render(SECRET, "/maze/abc", 65536);
        let links: Vec<_> = hrefs(&html)
            .into_iter()
            .filter(|h| h != CHALLENGE_PATH && !h.starts_with(&format!("{CHALLENGE_PATH}?")))
            .collect();
        assert!(links.len() >= 4);
        assert!(links.iter().all(|h| h.starts_with("/maze/abc/")));
    }

    #[test]
    fn request_path_is_escaped() {
        let html = render(SECRET, "/maze/\"><script>x</script>", 65536);
        assert!(!html.contains("<script>x"));
        assert!(html.contains("&quot;&gt;&lt;script&gt;"));
    }

    #[test]
    fn output_is_capped() {
        assert!(render(SECRET, "/maze/x", 500).len() <= 500);
    }
}
