use std::iter::Iterator;

use super::SeqNumber;

/// Iterator for compressing loss lists
pub struct CompressLossList<I> {
    /// Underlying iterator
    iterator: I,

    /// The next item
    next: Option<SeqNumber>,

    /// Some if looping
    last_in_loop: Option<SeqNumber>,
}

impl<I> Iterator for CompressLossList<I>
where
    I: Iterator<Item = SeqNumber>,
{
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        // if we're at the start, assign a next
        if self.next.is_none() {
            self.next = Some(self.iterator.next()?)
        }

        loop {
            // The state right here is
            // neither this nor next have been returned, and we need to figure out if this is
            // a) already in a loop and we continue on with that loop
            // b) already in a loop and need to break out
            // c) not in a loop and need to start one
            // d) not in a loop and doesn't need to start one

            let this = self.next?;
            match self.iterator.next() {
                Some(i) => self.next = Some(i),
                None => {
                    // invalidate next, so it None will be returned next time
                    self.next = None;

                    // return the one we have
                    return Some(this.as_raw());
                }
            };

            // the list must be sorted
            assert!(this < self.next?, "error: {}!<{}", this.0, self.next?.0);

            if let Some(last_in_loop) = self.last_in_loop {
                if last_in_loop + 2 == self.next? {
                    // continue with the loop
                    self.last_in_loop = Some(last_in_loop + 1);

                    continue;
                } else {
                    // break out of the loop
                    self.last_in_loop = None;

                    return Some(this.as_raw());
                }
            } else if this + 1 == self.next? {
                // create a loop
                self.last_in_loop = Some(this);

                // set the first bit to 1
                return Some(this.as_raw() | 1 << 31);
            } else {
                // no looping necessary
                return Some(this.as_raw());
            }
        }
    }
}

// keep in mind loss_list must be sorted
// takes in a list of u32, which is the loss list
pub fn compress_loss_list<I>(loss_list: I) -> CompressLossList<I>
where
    I: Iterator<Item = SeqNumber>,
{
    CompressLossList {
        iterator: loss_list,
        next: None,
        last_in_loop: None,
    }
}

/// The longest range of sequence numbers a single compressed loss entry may describe.
/// Larger ranges (and ranges whose end precedes their start) are invalid.
pub const MAX_LOSS_RANGE: u32 = 1 << 20;

const RANGE_START: u32 = 1 << 31;

/// Returns the inclusive end of a compressed range starting at `start`, if it is valid
fn range_end(start: SeqNumber, end: u32) -> Option<SeqNumber> {
    if end & RANGE_START != 0 {
        return None;
    }
    let end = SeqNumber::new_truncate(end);
    // the distance is measured modularly, so an end before the start is a very large distance
    (end - start < MAX_LOSS_RANGE).then_some(end)
}

/// Checks that every range in a compressed loss list is terminated, does not end before
/// it starts, and is of a reasonable size
pub fn is_valid_loss_list(loss_list: &[u32]) -> bool {
    let mut iter = loss_list.iter().copied();
    while let Some(next) = iter.next() {
        if next & RANGE_START != 0 {
            let start = SeqNumber::new_truncate(next & !RANGE_START);
            match iter.next() {
                Some(end) if range_end(start, end).is_some() => {}
                _ => return false,
            }
        }
    }
    true
}

pub struct DecompressLossList<I> {
    iterator: I,

    loop_next_end: Option<(SeqNumber, SeqNumber)>,
}

impl<I: Iterator<Item = u32>> Iterator for DecompressLossList<I> {
    type Item = SeqNumber;

    fn next(&mut self) -> Option<SeqNumber> {
        match self.loop_next_end {
            Some((next, end)) if next == end => {
                // loop is over
                self.loop_next_end = None;

                Some(next)
            }
            Some((next, end)) => {
                // continue the loop
                self.loop_next_end = Some((next + 1, end));

                Some(next)
            }
            None => {
                // no current loop
                let next = self.iterator.next()?;

                // is this a loop start
                if next & RANGE_START != 0 {
                    // set the first bit to zero
                    let next_num = SeqNumber::new_truncate(next & !RANGE_START);
                    // an unterminated or invalid range ends the list
                    let end = range_end(next_num, self.iterator.next()?)?;
                    self.loop_next_end = Some((next_num + 1, end));

                    Some(next_num)
                } else {
                    // no looping is possible
                    Some(SeqNumber::new_truncate(next))
                }
            }
        }
    }
}

pub fn decompress_loss_list<I: Iterator<Item = u32>>(loss_list: I) -> DecompressLossList<I> {
    DecompressLossList {
        iterator: loss_list,
        loop_next_end: None,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const ONE: u32 = 1 << 31;

    #[test]
    fn loss_compression_test() {
        macro_rules! test_comp_decomp {
            ($x:expr, $y:expr) => {{
                assert_eq!(
                    compress_loss_list($x.iter().cloned().map(SeqNumber::new_truncate))
                        .collect::<Vec<_>>(),
                    $y.iter().cloned().collect::<Vec<_>>(),
                    "Compressed wasn't same as given"
                );
                assert_eq!(
                    decompress_loss_list($y.iter().cloned()).collect::<Vec<_>>(),
                    $x.iter()
                        .cloned()
                        .map(SeqNumber::new_truncate)
                        .collect::<Vec<_>>(),
                    "Decompressed not same as given"
                );
            }};
        }

        test_comp_decomp!([13, 14, 15, 16, 17, 18, 19], [13 | ONE, 19]);

        test_comp_decomp!(
            [1, 2, 3, 4, 5, 9, 11, 12, 13, 16, 17],
            [1 | ONE, 5, 9, 11 | ONE, 13, 16 | ONE, 17]
        );

        test_comp_decomp!([15, 16], [15 | ONE, 16]);

        test_comp_decomp!(
            [1_687_761_238, 1_687_761_239],
            [1_687_761_238 | ONE, 1_687_761_239]
        );
    }

    #[test]
    #[should_panic(expected = "error: 10!<1")]
    fn invalid_ordering() {
        let _ = compress_loss_list([10, 1].iter().copied().map(SeqNumber::new_truncate))
            .collect::<Vec<_>>();
    }

    #[test]
    fn unterminated_loop() {
        assert!(decompress_loss_list([10 | ONE].iter().copied())
            .next()
            .is_none());
        assert!(!is_valid_loss_list(&[10 | ONE]));
    }

    #[test]
    fn reversed_range() {
        // an end before the start must not expand to a huge range
        assert_eq!(
            decompress_loss_list([100 | ONE, 10].iter().copied()).count(),
            0
        );
        assert!(!is_valid_loss_list(&[100 | ONE, 10]));
    }

    #[test]
    fn oversized_range() {
        assert!(!is_valid_loss_list(&[0 | ONE, MAX_LOSS_RANGE]));
        assert!(!is_valid_loss_list(&[0 | ONE, ONE]));
        assert_eq!(
            decompress_loss_list([0 | ONE, MAX_LOSS_RANGE].iter().copied()).count(),
            0
        );
        assert!(is_valid_loss_list(&[0 | ONE, MAX_LOSS_RANGE - 1]));
    }

    #[test]
    fn wrapping_range() {
        let max = SeqNumber::MAX - 1;
        assert_eq!(
            decompress_loss_list([(max - 1) | ONE, 1].iter().copied()).collect::<Vec<_>>(),
            [max - 1, max, 0, 1].map(SeqNumber::new_truncate)
        );
    }
}
