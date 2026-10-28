//! Byte-array bridge between RustCrypto hybrid-array and generic-ec-core 0.2.
use core::ops::{Deref, DerefMut};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
/// Encoding storage only; serialized by generic-ec through its byte slice.
pub struct WireBytes<B>(pub B);
impl<B: AsRef<[u8]>> AsRef<[u8]> for WireBytes<B> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl<B: AsMut<[u8]>> AsMut<[u8]> for WireBytes<B> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
impl<B: AsRef<[u8]>> Deref for WireBytes<B> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl<B: AsRef<[u8]> + AsMut<[u8]>> DerefMut for WireBytes<B> {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
impl<B> From<B> for WireBytes<B> {
    fn from(bytes: B) -> Self {
        Self(bytes)
    }
}
impl<B: AsRef<[u8]> + AsMut<[u8]> + Clone + Default + Send + Sync + 'static>
    generic_ec_core::ByteArray for WireBytes<B>
{
    fn zeroes() -> Self {
        Self(B::default())
    }
}
