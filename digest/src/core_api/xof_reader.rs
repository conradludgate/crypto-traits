use super::{AlgorithmName, XofReaderCore};
use crate::XofReader;
use block_buffer::EagerBuffer;
use core::fmt;

/// Wrapper around [`XofReaderCore`] implementations.
///
/// It handles data buffering and implements the mid-level traits.
pub struct XofReaderCoreWrapper<T: XofReaderCore> {
    pub(super) core: T,
    pub(super) buffer: EagerBuffer<T::Block>,
}
impl<T: XofReaderCore + Clone> Clone for XofReaderCoreWrapper<T>
where
    EagerBuffer<T::Block>: Clone,
{
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
            buffer: self.buffer.clone(),
        }
    }
}
impl<T: XofReaderCore + Default> Default for XofReaderCoreWrapper<T>
where
    EagerBuffer<T::Block>: Default,
{
    fn default() -> Self {
        Self {
            core: Default::default(),
            buffer: Default::default(),
        }
    }
}

impl<T: XofReaderCore + AlgorithmName> fmt::Debug for XofReaderCoreWrapper<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        T::write_alg_name(f)?;
        f.write_str(" { .. }")
    }
}

impl<T: XofReaderCore> XofReader for XofReaderCoreWrapper<T> {
    #[inline]
    fn read(&mut self, buffer: &mut [u8]) {
        let Self { core, buffer: buf } = self;
        buf.set_data(buffer, |blocks| {
            for block in blocks {
                *block = core.read_block();
            }
        });
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl<T: XofReaderCore> std::io::Read for XofReaderCoreWrapper<T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        XofReader::read(self, buf);
        Ok(buf.len())
    }
}
