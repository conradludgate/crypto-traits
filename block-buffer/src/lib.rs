//! Fixed size buffer for block processing of data.
#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_root_url = "https://docs.rs/block-buffer/0.10.2"
)]
#![warn(missing_docs, rust_2018_idioms)]

use core::{marker::PhantomData, slice};

use array::Array;

mod sealed;

/// Trait for buffer kinds.
pub trait BufferKind: sealed::Sealed {}

/// Eager block buffer kind, which guarantees that buffer position
/// always lies in the range of `0..BlockSize`.
#[derive(Copy, Clone, Debug, Default)]
pub struct Eager {}

/// Lazy block buffer kind, which guarantees that buffer position
/// always lies in the range of `0..=BlockSize`.
#[derive(Copy, Clone, Debug, Default)]
pub struct Lazy {}

impl BufferKind for Eager {}
impl BufferKind for Lazy {}

/// Eager block buffer.
pub type EagerBuffer<B> = BlockBuffer<B, Eager>;
/// Lazy block buffer.
pub type LazyBuffer<B> = BlockBuffer<B, Lazy>;

/// Buffer for block processing of data.
#[derive(Debug)]
pub struct BlockBuffer<Buffer, Kind: BufferKind> {
    buffer: Buffer,
    pos: u8,
    _pd: PhantomData<Kind>,
}

impl<Kind: BufferKind, Block: Array> Default for BlockBuffer<Block, Kind> {
    fn default() -> Self {
        Self {
            buffer: Block::zero(),
            pos: 0,
            _pd: PhantomData,
        }
    }
}

impl<Kind: BufferKind, Block: Array> Clone for BlockBuffer<Block, Kind> {
    fn clone(&self) -> Self {
        Self {
            buffer: self.buffer,
            pos: self.pos,
            _pd: PhantomData,
        }
    }
}

impl<Kind: BufferKind, Block: Array> BlockBuffer<Block, Kind> {
    /// Create new buffer from slice.
    ///
    /// # Panics
    /// If slice length is not valid for used buffer kind.
    #[inline(always)]
    pub fn new(buf: &[u8]) -> Self {
        let pos = buf.len();
        assert!(Kind::invariant(pos, Block::LEN));
        let mut buffer = Block::zero();
        buffer.as_mut()[..pos].copy_from_slice(buf);
        Self {
            buffer,
            pos: pos as u8,
            _pd: PhantomData,
        }
    }

    /// Digest data in `input` in blocks of size `BlockSize` using
    /// the `compress` function, which accepts slice of blocks.
    #[inline]
    pub fn digest_blocks(&mut self, mut input: &[u8], mut compress: impl FnMut(&[Block])) {
        let pos = self.get_pos();
        // using `self.remaining()` for some reason
        // prevents panic elimination
        let rem = self.size() - pos;
        let n = input.len();
        // Note that checking condition `pos + n < BlockSize` is
        // equivalent to checking `n < rem`, where `rem` is equal
        // to `BlockSize - pos`. Using the latter allows us to work
        // around compiler accounting for possible overflow of
        // `pos + n` which results in it inserting unreachable
        // panic branches. Using `unreachable_unchecked` in `get_pos`
        // we convince compiler that `BlockSize - pos` never underflows.
        if Kind::invariant(n, rem) {
            // double slicing allows to remove panic branches
            self.buffer.as_mut()[pos..][..n].copy_from_slice(input);
            self.set_pos_unchecked(pos + n);
            return;
        }
        if pos != 0 {
            let (left, right) = input.split_at(rem);
            input = right;
            self.buffer.as_mut()[pos..].copy_from_slice(left);
            compress(slice::from_ref(&self.buffer));
        }

        let (blocks, leftover) = Kind::split_blocks(input);
        if !blocks.is_empty() {
            compress(blocks);
        }

        let n = leftover.len();
        self.buffer.as_mut()[..n].copy_from_slice(leftover);
        self.set_pos_unchecked(n);
    }

    /// Reset buffer by setting cursor position to zero.
    #[inline(always)]
    pub fn reset(&mut self) {
        self.set_pos_unchecked(0);
    }

    /// Pad remaining data with zeros and return resulting block.
    #[inline(always)]
    pub fn pad_with_zeros(&mut self) -> &mut Block {
        let pos = self.get_pos();
        self.buffer.as_mut()[pos..].iter_mut().for_each(|b| *b = 0);
        self.set_pos_unchecked(0);
        &mut self.buffer
    }

    /// Return current cursor position.
    #[inline(always)]
    pub fn get_pos(&self) -> usize {
        let pos = self.pos as usize;
        if !Kind::invariant(pos, Block::LEN) {
            debug_assert!(false);
            // SAFETY: `pos` never breaks the invariant
            unsafe {
                core::hint::unreachable_unchecked();
            }
        }
        pos
    }

    /// Return slice of data stored inside the buffer.
    #[inline(always)]
    pub fn get_data(&self) -> &[u8] {
        &self.buffer.as_ref()[..self.get_pos()]
    }

    /// Set buffer content and cursor position.
    ///
    /// # Panics
    /// If `pos` is bigger or equal to block size.
    #[inline]
    pub fn set(&mut self, buf: Block, pos: usize) {
        assert!(Kind::invariant(pos, Block::LEN));
        self.buffer = buf;
        self.set_pos_unchecked(pos);
    }

    /// Return size of the internall buffer in bytes.
    #[inline(always)]
    pub fn size(&self) -> usize {
        Block::LEN
    }

    /// Return number of remaining bytes in the internall buffer.
    #[inline(always)]
    pub fn remaining(&self) -> usize {
        self.size() - self.get_pos()
    }

    #[inline(always)]
    fn set_pos_unchecked(&mut self, pos: usize) {
        debug_assert!(Kind::invariant(pos, Block::LEN));
        self.pos = pos as u8;
    }
}

impl<Block: Array> BlockBuffer<Block, Eager> {
    /// Set `data` to generated blocks.
    #[inline]
    pub fn set_data(
        &mut self,
        mut data: &mut [u8],
        mut process_blocks: impl FnMut(&mut [Block]),
    ) {
        let pos = self.get_pos();
        let r = self.remaining();
        let n = data.len();
        if pos != 0 {
            if n < r {
                // double slicing allows to remove panic branches
                data.copy_from_slice(&self.buffer.as_ref()[pos..][..n]);
                self.set_pos_unchecked(pos + n);
                return;
            }
            let (left, right) = data.split_at_mut(r);
            data = right;
            left.copy_from_slice(&self.buffer.as_ref()[pos..]);
        }

        let (blocks, leftover) = to_blocks_mut(data);
        process_blocks(blocks);

        let n = leftover.len();
        if n != 0 {
            let mut block = Block::zero();
            process_blocks(slice::from_mut(&mut block));
            leftover.copy_from_slice(&block.as_ref()[..n]);
            self.buffer = block;
        }
        self.set_pos_unchecked(n);
    }

    /// Compress remaining data after padding it with `delim`, zeros and
    /// the `suffix` bytes. If there is not enough unused space, `compress`
    /// will be called twice.
    ///
    /// # Panics
    /// If suffix length is bigger than block size.
    #[inline(always)]
    pub fn digest_pad(&mut self, delim: u8, suffix: &[u8], mut compress: impl FnMut(&Block)) {
        if suffix.len() > Block::LEN {
            panic!("suffix is too long");
        }
        let pos = self.get_pos();
        self.buffer.as_mut()[pos] = delim;
        for b in &mut self.buffer.as_mut()[pos + 1..] {
            *b = 0;
        }

        let n = self.size() - suffix.len();
        if self.size() - pos - 1 < suffix.len() {
            compress(&self.buffer);
            let mut block = Block::zero();
            block.as_mut()[n..].copy_from_slice(suffix);
            compress(&block);
        } else {
            self.buffer.as_mut()[n..].copy_from_slice(suffix);
            compress(&self.buffer);
        }
        self.set_pos_unchecked(0)
    }

    /// Pad message with 0x80, zeros and 64-bit message length using
    /// big-endian byte order.
    #[inline]
    pub fn len64_padding_be(&mut self, data_len: u64, compress: impl FnMut(&Block)) {
        self.digest_pad(0x80, &data_len.to_be_bytes(), compress);
    }

    /// Pad message with 0x80, zeros and 64-bit message length using
    /// little-endian byte order.
    #[inline]
    pub fn len64_padding_le(&mut self, data_len: u64, compress: impl FnMut(&Block)) {
        self.digest_pad(0x80, &data_len.to_le_bytes(), compress);
    }

    /// Pad message with 0x80, zeros and 128-bit message length using
    /// big-endian byte order.
    #[inline]
    pub fn len128_padding_be(&mut self, data_len: u128, compress: impl FnMut(&Block)) {
        self.digest_pad(0x80, &data_len.to_be_bytes(), compress);
    }
}

/// Split message into mutable slice of parallel blocks, blocks, and leftover bytes.
#[inline(always)]
fn to_blocks_mut<Block: Array>(data: &mut [u8]) -> (&mut [Block], &mut [u8]) {
    let nb = data.len() / Block::LEN;
    let (left, right) = data.split_at_mut(nb * Block::LEN);
    let p = left.as_mut_ptr() as *mut Block;
    // SAFETY: we guarantee that `blocks` does not point outside of `data`, and `p` is valid for
    // mutation
    let blocks = unsafe { slice::from_raw_parts_mut(p, nb) };
    (blocks, right)
}
