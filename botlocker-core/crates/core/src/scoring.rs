use std::collections::HashSet;

use crate::config::Config;
use crate::signals::{Family, Hit};

#[derive(Debug, Clone, Default)]
pub struct Score {
    pub total: f64,
    pub hits: Vec<Hit>,
}

impl Score {
    pub fn families(&self) -> usize {
        self.hits
            .iter()
            .map(|h| h.family)
            .collect::<HashSet<Family>>()
            .len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Proxy,
    Challenge,
    Trap,
}

/// Trapping needs a high score from at least two independent signal families,
/// so one noisy signal can never trap a visitor on its own.
pub fn decide(score: &Score, cfg: &Config) -> Action {
    if score.total >= cfg.trap_at && score.families() >= 2 {
        Action::Trap
    } else if score.total >= cfg.challenge_at {
        Action::Challenge
    } else {
        Action::Proxy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::from_toml(
            r#"
            origin = "https://origin.example"
            maze_prefix = "/maze/"
            challenge_at = 3.0
            trap_at = 6.0
            "#,
        )
        .unwrap()
    }

    fn hit(family: Family, weight: f64) -> Hit {
        Hit {
            id: "test",
            family,
            weight,
            evidence: String::new(),
        }
    }

    #[test]
    fn low_score_proxies() {
        let s = Score {
            total: 1.0,
            hits: vec![hit(Family::Headers, 1.0)],
        };
        assert_eq!(decide(&s, &cfg()), Action::Proxy);
    }

    #[test]
    fn mid_score_challenges() {
        let s = Score {
            total: 4.0,
            hits: vec![hit(Family::Headers, 1.5), hit(Family::Client, 2.5)],
        };
        assert_eq!(decide(&s, &cfg()), Action::Challenge);
    }

    #[test]
    fn high_score_from_one_family_only_challenges() {
        let s = Score {
            total: 7.0,
            hits: vec![hit(Family::Client, 4.0), hit(Family::Client, 3.0)],
        };
        assert_eq!(decide(&s, &cfg()), Action::Challenge);
    }

    #[test]
    fn high_score_from_two_families_traps() {
        let s = Score {
            total: 6.0,
            hits: vec![hit(Family::Client, 4.0), hit(Family::Network, 2.0)],
        };
        assert_eq!(decide(&s, &cfg()), Action::Trap);
    }
}
