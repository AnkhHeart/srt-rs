use std::{
    collections::hash_map::RandomState,
    hash::BuildHasher,
    net::SocketAddr,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

/// Keyed with a random secret chosen once per process, so cookies cannot be predicted
/// by a remote peer
fn hasher() -> &'static RandomState {
    static HASHER: OnceLock<RandomState> = OnceLock::new();
    HASHER.get_or_init(RandomState::new)
}

fn cookie_for_minute(saddr: &SocketAddr, time_mins: u64) -> i32 {
    hasher().hash_one((saddr, time_mins)) as u32 as i32
}

pub fn gen_cookie(saddr: &SocketAddr) -> i32 {
    let time_mins = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time was before the the unix epoch!!!")
        .as_secs()
        / 60;

    cookie_for_minute(saddr, time_mins)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn cookie_depends_on_address_and_time() {
        let a: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let b: SocketAddr = "127.0.0.2:2000".parse().unwrap();

        assert_eq!(cookie_for_minute(&a, 100), cookie_for_minute(&a, 100));
        assert_ne!(cookie_for_minute(&a, 100), cookie_for_minute(&b, 100));
        assert_ne!(cookie_for_minute(&a, 100), cookie_for_minute(&a, 101));
    }

    #[test]
    fn cookie_differs_between_addresses() {
        let a: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:2001".parse().unwrap();

        assert_ne!(gen_cookie(&a), gen_cookie(&b));
    }
}
