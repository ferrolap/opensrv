// Copyright 2021 Datafuse Labs.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io;
use std::io::prelude::*;

use std::iter::Enumerate;
use std::marker::PhantomData;
use std::ops::RangeFrom;

use bytes::BytesMut;
use nom::Needed;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;

const PACKET_BUFFER_SIZE: usize = 4_096;
const PACKET_LARGE_BUFFER_SIZE: usize = 1_048_576;

/// Calculate the new buffer size for the next read
fn calc_new_buf_size(last_buf_size: usize) -> usize {
    if last_buf_size >= PACKET_BUFFER_SIZE * 2 {
        // if packet is already too large, use larger buffer to avoid multiple allocation
        PACKET_LARGE_BUFFER_SIZE
    } else {
        std::cmp::max(PACKET_BUFFER_SIZE, last_buf_size * 2)
    }
}

/// reuse old buffer if possible, otherwise create a new buffer
///
/// return (the idx to start writing to the buffer,  and the buffer itself)
///
/// will copy the remain bytes from the old buffer to the new buffer if reusing
fn reuse_or_create_buf(old_buf: bytes::Bytes, last_buf_size: usize) -> (usize, BytesMut) {
    let new_buf_size = calc_new_buf_size(last_buf_size);
    match old_buf.try_into_mut() {
        Ok(mut unique) => {
            let len = unique.len();
            let resize_buf = if new_buf_size <= len {
                // if new buffer is smaller than old buffer, just double the size
                len * 2
            } else {
                new_buf_size
            };
            debug_assert!(len < resize_buf);
            // resize will save old bytes unchanged and fill the rest with 0
            unique.resize(resize_buf, 0);
            (len, unique)
        }
        Err(remain) => {
            let mut buf = BytesMut::with_capacity(new_buf_size);
            buf.resize(new_buf_size, 0);
            // if old buffer still contain bytes unread, need to save those bytes too
            buf[0..remain.len()].copy_from_slice(&remain);
            (remain.len(), buf)
        }
    }
}

pub struct PacketReader<R> {
    bytes: bytes::Bytes,
    pub r: R,
}

impl<R> PacketReader<R> {
    pub fn new(r: R) -> Self {
        PacketReader {
            bytes: bytes::Bytes::new(),
            r,
        }
    }
}

impl<R: Read> PacketReader<R> {
    #[allow(dead_code)]
    pub fn next(&mut self) -> io::Result<Option<(u8, Packet<'_>)>> {
        loop {
            let last_buffer_size = self.bytes.len();
            if !self.bytes.is_empty() {
                // coping `bytes::Bytes` are very cheap, just move the pointer and increase the ref count.
                match packet(self.bytes.clone().into()) {
                    Ok((rest, p)) => {
                        // most time the `rest` is either empty or very small, so it's cheap to copy it later into next buffer
                        self.bytes = rest.into();
                        return Ok(Some(p));
                    }
                    Err(nom::Err::Incomplete(_)) | Err(nom::Err::Error(_)) => {}
                    Err(nom::Err::Failure(ctx)) => {
                        let err = Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("{ctx:?}"),
                        ));
                        return err;
                    }
                }
            }

            // read more buffer
            let (start, mut buf) =
                reuse_or_create_buf(std::mem::take(&mut self.bytes), last_buffer_size);
            let read_cnt = self.r.read(&mut buf[start..])?;
            buf.truncate(start + read_cnt);
            self.bytes = buf.freeze();

            // for a [TcpStream], returning zero indicates the connection was shut down correctly.
            if read_cnt == 0 {
                if self.bytes.is_empty() {
                    return Ok(None);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("{} unhandled bytes", self.bytes.len()),
                    ));
                }
            }
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PacketReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // if our buffer have content, send those immediately
        if !self.bytes.is_empty() {
            buf.put_slice(&self.bytes);
            self.bytes.clear();
            std::task::Poll::Ready(Ok(()))
        } else {
            std::pin::Pin::new(&mut self.r).poll_read(cx, buf)
        }
    }
}

/// Upper bound on bytes that read-ahead may hold in the packet buffer while a
/// query is executing. Read-ahead also stops as soon as the buffered bytes can no
/// longer be a `COM_QUIT` packet, so in practice the buffer grows by one read.
pub(crate) const READ_AHEAD_LIMIT: usize = 4_096;

/// Outcome of one read-ahead step while a query is executing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadAhead {
    /// The peer is gone: EOF (FIN) or a connection reset / abort / broken pipe.
    Disconnected,
    /// A complete `COM_QUIT` packet is at the head of the buffer.
    Quit,
    /// The buffered bytes might still become a `COM_QUIT` packet; read again.
    More,
    /// Pipelined data, the buffer limit, or another I/O error: stop reading
    /// ahead for the rest of this query and do not report a disconnect.
    Stop,
}

/// Classify buffered bytes for read-ahead: `Some(Quit)`, `Some(Stop)`, or
/// `None` when more bytes are needed to decide.
fn classify_read_ahead(bytes: &[u8]) -> Option<ReadAhead> {
    // A COM_QUIT packet is exactly: length 1 (u24 LE), any sequence id, 0x01.
    const QUIT_LEN: [u8; 3] = [0x01, 0x00, 0x00];
    if bytes.len() < 3 {
        return if QUIT_LEN.starts_with(bytes) {
            None
        } else {
            Some(ReadAhead::Stop)
        };
    }
    if bytes[..3] != QUIT_LEN {
        return Some(ReadAhead::Stop);
    }
    match bytes.get(4) {
        None => None,
        Some(0x01) => Some(ReadAhead::Quit),
        Some(_) => Some(ReadAhead::Stop),
    }
}

impl<R: AsyncRead + Unpin> PacketReader<R> {
    /// Read ahead while a query is executing, appending any bytes to the packet
    /// buffer so that the next [`Self::next_async`] sees them unchanged.
    ///
    /// Cancel safe: the buffer is only modified after the read completes, so
    /// dropping the future at its await point loses no data.
    pub(crate) async fn read_ahead(&mut self) -> ReadAhead {
        if let Some(outcome) = classify_read_ahead(&self.bytes) {
            return outcome;
        }
        let room = READ_AHEAD_LIMIT.saturating_sub(self.bytes.len());
        if room == 0 {
            return ReadAhead::Stop;
        }
        let mut chunk = [0u8; 512];
        let want = room.min(chunk.len());
        match self.r.read(&mut chunk[..want]).await {
            Ok(0) => ReadAhead::Disconnected,
            Ok(n) => {
                let mut buf = BytesMut::with_capacity(self.bytes.len() + n);
                buf.extend_from_slice(&self.bytes);
                buf.extend_from_slice(&chunk[..n]);
                self.bytes = buf.freeze();
                classify_read_ahead(&self.bytes).unwrap_or(ReadAhead::More)
            }
            Err(e) => match e.kind() {
                io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::NotConnected
                | io::ErrorKind::UnexpectedEof => ReadAhead::Disconnected,
                _ => ReadAhead::Stop,
            },
        }
    }
}

impl<R: AsyncRead + Unpin> PacketReader<R> {
    pub async fn next_async(&mut self) -> io::Result<Option<(u8, Packet<'_>)>> {
        loop {
            let last_buffer_size = self.bytes.len();
            if !self.bytes.is_empty() {
                match packet(self.bytes.clone().into()) {
                    Ok((rest, p)) => {
                        self.bytes = rest.into();
                        return Ok(Some(p));
                    }
                    Err(nom::Err::Incomplete(_)) | Err(nom::Err::Error(_)) => {}
                    Err(nom::Err::Failure(ctx)) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("{ctx:?}"),
                        ));
                    }
                }
            }

            // read more buffer
            let (start, mut buf) =
                reuse_or_create_buf(std::mem::take(&mut self.bytes), last_buffer_size);

            let read_cnt = self.r.read(&mut buf[start..]).await?;
            buf.truncate(start + read_cnt);

            self.bytes = buf.freeze();

            if read_cnt == 0 {
                if self.bytes.is_empty() {
                    return Ok(None);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("{} unhandled bytes", self.bytes.len()),
                    ));
                }
            }
        }
    }
}

pub fn fullpacket(i: NomBytes) -> nom::IResult<NomBytes, (u8, NomBytes)> {
    let (i, _) = nom::bytes::complete::tag(&[0xff, 0xff, 0xff][..])(i)?;
    let (i, seq) = nom::bytes::complete::take(1u8)(i)?;
    let (i, bytes) = nom::bytes::complete::take(U24_MAX)(i)?;
    Ok((i, (seq.as_ref()[0], bytes)))
}

pub fn onepacket(i: NomBytes) -> nom::IResult<NomBytes, (u8, NomBytes)> {
    let (i, length) = nom::number::complete::le_u24(i)?;
    let (i, seq) = nom::bytes::complete::take(1u8)(i)?;
    let (i, bytes) = nom::bytes::complete::take(length)(i)?;
    Ok((i, (seq.as_ref()[0], bytes)))
}

/// Bytes wrapper for nom, allowing nom to parse bytes::Bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NomBytes(bytes::Bytes);

impl NomBytes {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<&[u8]> for NomBytes {
    fn from(value: &[u8]) -> Self {
        NomBytes(bytes::Bytes::copy_from_slice(value))
    }
}

impl From<bytes::Bytes> for NomBytes {
    fn from(value: bytes::Bytes) -> Self {
        NomBytes(value)
    }
}

impl From<NomBytes> for bytes::Bytes {
    fn from(value: NomBytes) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for NomBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl nom::InputTake for NomBytes {
    fn take(&self, count: usize) -> Self {
        NomBytes(self.0.slice(0..count))
    }

    fn take_split(&self, count: usize) -> (Self, Self) {
        let mut prefix = self.0.clone();
        let suffix = prefix.split_off(count);
        (NomBytes(suffix), NomBytes(prefix))
    }
}

impl nom::Compare<&[u8]> for NomBytes {
    fn compare(&self, t: &[u8]) -> nom::CompareResult {
        self.0.as_ref().compare(t)
    }

    fn compare_no_case(&self, t: &[u8]) -> nom::CompareResult {
        self.0.as_ref().compare_no_case(t)
    }
}

impl nom::InputLength for NomBytes {
    fn input_len(&self) -> usize {
        self.0.len()
    }
}

impl nom::InputIter for NomBytes {
    type Item = u8;
    type Iter = Enumerate<Self::IterElem>;
    type IterElem = bytes::buf::IntoIter<bytes::Bytes>;

    #[inline]
    fn iter_indices(&self) -> Self::Iter {
        self.iter_elements().enumerate()
    }
    #[inline]
    fn iter_elements(&self) -> Self::IterElem {
        self.0.clone().into_iter()
    }
    #[inline]
    fn position<P>(&self, predicate: P) -> Option<usize>
    where
        P: Fn(Self::Item) -> bool,
    {
        self.0.iter().position(|b| predicate(*b))
    }
    #[inline]
    fn slice_index(&self, count: usize) -> Result<usize, Needed> {
        if self.0.len() >= count {
            Ok(count)
        } else {
            Err(Needed::new(count - self.0.len()))
        }
    }
}

impl nom::Slice<RangeFrom<usize>> for NomBytes {
    fn slice(&self, range: RangeFrom<usize>) -> Self {
        NomBytes(self.0.slice(range))
    }
}

// a simple wrapper around bytes::Bytes to make sure interface stays the same
#[derive(Clone)]
pub struct Packet<'a> {
    bytes: bytes::Bytes,
    _lifetime: PhantomData<&'a ()>, // NOTE: the lifetime can be removed since Bytes mangaes the lifetime by itself
}

impl Packet<'_> {
    fn from_bytes(bytes: bytes::Bytes) -> Self {
        Packet {
            bytes,
            _lifetime: PhantomData,
        }
    }
}

use crate::U24_MAX;
use std::ops::Deref;

impl Deref for Packet<'_> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.bytes.as_ref()
    }
}

// note that for small packet, this function is zero-copy, but for packet >= 2^24 it currently copy stuff, this await further optimization
pub(crate) fn packet<'a>(i: NomBytes) -> nom::IResult<NomBytes, (u8, Packet<'a>)> {
    nom::combinator::map(
        nom::sequence::pair(
            nom::multi::fold_many0(
                fullpacket,
                || (0, None),
                |(seq, pkt): (_, Option<BytesMut>), (nseq, p)| {
                    let pkt = if let Some(mut pkt) = pkt {
                        assert_eq!(nseq, seq + 1);
                        pkt.extend_from_slice(p.as_ref());
                        Some(pkt)
                    } else {
                        // TODO: avoid copy
                        Some(BytesMut::from(p.0))
                    };
                    (nseq, pkt)
                },
            ),
            nom::combinator::opt(onepacket),
        ),
        move |((full_seq, full_pkt), last)| match (full_pkt, last) {
            (Some(mut full_pkt), Some((last_seq, last_pkt))) => {
                assert_eq!(last_seq, full_seq + 1);
                full_pkt.extend_from_slice(last_pkt.as_ref());
                let final_pkt = full_pkt.freeze();
                Ok((last_seq, Packet::from_bytes(final_pkt)))
            }
            (Some(full_pkt), None) => Ok((full_seq, Packet::from_bytes(full_pkt.freeze()))),
            (None, Some((last_seq, last_pkt))) => Ok((last_seq, Packet::from_bytes(last_pkt.0))),
            // TODO: might know length
            (None, None) => Err(nom::Err::Incomplete(Needed::Unknown)),
        },
    )(i)
    .map(|(rest, parsed)| match parsed {
        Ok(parsed) => Ok((rest, parsed)),
        Err(e) => Err(e),
    })?
}

#[cfg(test)]
mod test {
    use bytes::{Buf, BufMut};

    use super::*;

    fn mock_packet(mut data: bytes::Bytes, start_seq: u8) -> bytes::Bytes {
        let mut buf = BytesMut::new();
        let mut seq = start_seq;
        while data.len() > U24_MAX {
            buf.extend_from_slice(&[0xff, 0xff, 0xff]);
            buf.put_u8(seq);
            buf.put(&data[0..U24_MAX]);
            data.advance(U24_MAX);
            seq += 1;
        }
        if !data.is_empty() {
            let le_u64: [u8; 8] = data.len().to_le_bytes();
            let le_u24 = &le_u64[0..3];
            buf.extend_from_slice(le_u24);
            buf.put_u8(seq);
            buf.put(data);
        }
        buf.freeze()
    }

    #[tokio::test]
    async fn test_various_packet_size() {
        // test for off by one, and off by header size(3 bytes for length and 1 for seq num)
        let testcases = [
            0,
            1,
            2,
            PACKET_BUFFER_SIZE - 1 - 4,
            PACKET_BUFFER_SIZE - 1,
            PACKET_BUFFER_SIZE,
            PACKET_BUFFER_SIZE + 1,
            PACKET_BUFFER_SIZE + 1 + 4,
            PACKET_LARGE_BUFFER_SIZE - 4 - 1,
            PACKET_LARGE_BUFFER_SIZE - 4,
            PACKET_LARGE_BUFFER_SIZE - 1,
            PACKET_LARGE_BUFFER_SIZE,
            PACKET_LARGE_BUFFER_SIZE + 1,
            PACKET_LARGE_BUFFER_SIZE + 4,
            PACKET_LARGE_BUFFER_SIZE + 4 + 1,
            U24_MAX - 4 - 1,
            U24_MAX - 4,
            U24_MAX - 1,
            U24_MAX,
            U24_MAX + 1,
            U24_MAX + 4,
            U24_MAX + 4 + 1,
            U24_MAX * 2 - 4 - 1,
            U24_MAX * 2 - 4,
            U24_MAX * 2 - 1,
            U24_MAX * 2,
            U24_MAX * 2 + 1,
            U24_MAX * 2 + 4,
            U24_MAX * 2 + 4 + 1,
        ];
        for input_size in testcases {
            let large_data = bytes::Bytes::from(vec![0; input_size]);
            let packet = mock_packet(large_data, 0);
            let mut reader = PacketReader::new(packet.reader());
            let mut last_seq = 0;
            let mut total_size = 0;
            while let Some((seq, packet)) = reader.next().unwrap() {
                if seq != 0 {
                    assert!(seq > last_seq);
                }
                total_size += packet.len();
                last_seq = seq;
            }
            assert_eq!(total_size, input_size);
        }
        for input_size in testcases {
            let large_data = bytes::Bytes::from(vec![0; input_size]);
            let packet = mock_packet(large_data, 0);
            let mut reader = PacketReader::new(packet.as_ref());
            let mut last_seq = 0;
            let mut total_size = 0;
            while let Some((seq, packet)) = reader.next_async().await.unwrap() {
                if seq != 0 {
                    assert!(seq > last_seq);
                }
                total_size += packet.len();
                last_seq = seq;
            }
            assert_eq!(total_size, input_size);
        }
    }
}

#[cfg(test)]
mod read_ahead_tests {
    use super::*;

    #[test]
    fn classify_read_ahead_only_reports_a_complete_quit() {
        assert_eq!(classify_read_ahead(&[]), None);
        assert_eq!(classify_read_ahead(&[0x01]), None);
        assert_eq!(classify_read_ahead(&[0x01, 0x00, 0x00, 0x00]), None);
        assert_eq!(
            classify_read_ahead(&[0x01, 0x00, 0x00, 0x00, 0x01]),
            Some(ReadAhead::Quit)
        );
        // COM_PING (0x0e) and a pipelined COM_QUERY are not a disconnect.
        assert_eq!(
            classify_read_ahead(&[0x01, 0x00, 0x00, 0x00, 0x0e]),
            Some(ReadAhead::Stop)
        );
        assert_eq!(classify_read_ahead(&[0x09, 0x00]), Some(ReadAhead::Stop));
        assert_eq!(
            classify_read_ahead(&[0x09, 0x00, 0x00, 0x00, 0x03, b'S']),
            Some(ReadAhead::Stop)
        );
        // A quit packet behind pipelined data is not looked at.
        assert_eq!(
            classify_read_ahead(&[
                0x02, 0x00, 0x00, 0x00, 0x03, b'x', 0x01, 0x00, 0x00, 0x00, 0x01
            ]),
            Some(ReadAhead::Stop)
        );
    }

    #[tokio::test]
    async fn read_ahead_keeps_bytes_for_next_async() {
        let data: &[u8] = &[0x02, 0x00, 0x00, 0x00, 0x03, b'x'];
        let mut reader = PacketReader::new(data);
        assert_eq!(reader.read_ahead().await, ReadAhead::Stop);
        assert_eq!(reader.read_ahead().await, ReadAhead::Stop);
        let (seq, packet) = reader.next_async().await.unwrap().unwrap();
        assert_eq!(seq, 0);
        assert_eq!(&*packet, &[0x03, b'x']);
        assert!(reader.next_async().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_ahead_reports_eof_and_quit() {
        let mut reader = PacketReader::new(&[][..]);
        assert_eq!(reader.read_ahead().await, ReadAhead::Disconnected);
        let quit: &[u8] = &[0x01, 0x00, 0x00, 0x00, 0x01];
        let mut reader = PacketReader::new(quit);
        assert_eq!(reader.read_ahead().await, ReadAhead::Quit);
        let (_seq, packet) = reader.next_async().await.unwrap().unwrap();
        assert_eq!(&*packet, &[0x01]);
    }
}
