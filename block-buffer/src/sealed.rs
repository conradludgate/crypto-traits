use core::slice;

use array::Array;

/// Sealed trait for buffer kinds.
pub trait Sealed {
    /// Invariant guaranteed by a buffer kind, i.e. with correct
    /// buffer code this function always returns true.
    fn invariant(pos: usize, block_size: usize) -> bool;

    /// Split input data into slice fo blocks and tail.
    fn split_blocks<Block: Array>(data: &[u8]) -> (&[Block], &[u8]);
}

impl Sealed for super::Eager {
    #[inline(always)]
    fn invariant(pos: usize, block_size: usize) -> bool {
        pos < block_size
    }

    #[inline(always)]
    fn split_blocks<Block: Array>(data: &[u8]) -> (&[Block], &[u8]) {
        let nb = data.len() / Block::LEN;
        let blocks_len = nb * Block::LEN;
        let tail_len = data.len() - blocks_len;
        // SAFETY: we guarantee that created slices do not point
        // outside of `data`
        unsafe {
            let blocks_ptr = data.as_ptr() as *const Block;
            let tail_ptr = data.as_ptr().add(blocks_len);
            (
                slice::from_raw_parts(blocks_ptr, nb),
                slice::from_raw_parts(tail_ptr, tail_len),
            )
        }
    }
}

impl Sealed for super::Lazy {
    #[inline(always)]
    fn invariant(pos: usize, block_size: usize) -> bool {
        pos <= block_size
    }

    #[inline(always)]
    fn split_blocks<Block: Array>(data: &[u8]) -> (&[Block], &[u8]) {
        if data.is_empty() {
            return (&[], &[]);
        }
        let (nb, tail_len) = if data.len() % Block::LEN == 0 {
            (data.len() / Block::LEN - 1, Block::LEN)
        } else {
            let nb = data.len() / Block::LEN;
            (nb, data.len() - nb * Block::LEN)
        };
        let blocks_len = nb * Block::LEN;
        // SAFETY: we guarantee that created slices do not point
        // outside of `data`
        unsafe {
            let blocks_ptr = data.as_ptr() as *const Block;
            let tail_ptr = data.as_ptr().add(blocks_len);
            (
                slice::from_raw_parts(blocks_ptr, nb),
                slice::from_raw_parts(tail_ptr, tail_len),
            )
        }
    }
}
