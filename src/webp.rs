//! The configuration half of `golang.org/x/image/webp` (v0.46.0): the RIFF
//! container (`x/image/riff`), the VP8 key frame header
//! (`vp8.Decoder.DecodeFrameHeader`), the VP8L header (`vp8l.DecodeConfig`)
//! and the VP8X chunk, enough for `image.DecodeConfig`. The server only ever
//! asks for an upload's dimensions and format, never its pixels, so the
//! format registers with a `decode` that fails.
//!
//! Go's configuration path answers at the first VP8X, VP8 or VP8L chunk, so
//! an ALPH chunk, which only follows a VP8X, is always out of place here.

use std::io::{self, Read};
use std::sync::Once;

use rust_stdlib::image::{self, color::Model, Config};

const CHUNK_HEADER_SIZE: u32 = 8;
const FCC_ALPH: [u8; 4] = *b"ALPH";
const FCC_VP8: [u8; 4] = *b"VP8 ";
const FCC_VP8L: [u8; 4] = *b"VP8L";
const FCC_VP8X: [u8; 4] = *b"VP8X";
const FCC_WEBP: [u8; 4] = *b"WEBP";

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

fn invalid_format() -> io::Error {
    invalid("webp: invalid format")
}

fn read_full(r: &mut dyn Read, buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    if filled == 0 { "EOF" } else { "unexpected EOF" },
                ))
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// `riff.Reader` for the chunks of one RIFF list, reading each chunk's data
/// through `read_chunk` and draining what the caller did not read.
struct RiffReader<'a> {
    r: &'a mut dyn Read,
    total_len: u32,
    chunk_len: u32,
    /// What the caller has read of the current chunk.
    chunk_read: u32,
    padded: bool,
}

impl<'a> RiffReader<'a> {
    /// `riff.NewReader`: reads the RIFF header and returns the form type.
    fn new(r: &'a mut dyn Read) -> io::Result<([u8; 4], RiffReader<'a>)> {
        let mut buf = [0u8; CHUNK_HEADER_SIZE as usize];
        read_full(r, &mut buf).map_err(|_| invalid("riff: missing RIFF chunk header"))?;
        if &buf[..4] != b"RIFF" {
            return Err(invalid("riff: missing RIFF chunk header"));
        }
        let list_len = u32_le(&buf[4..]);
        if list_len < 4 {
            return Err(invalid("riff: short chunk data"));
        }
        let mut form = [0u8; 4];
        read_full(r, &mut form).map_err(|_| invalid("riff: missing RIFF chunk header"))?;
        Ok((
            form,
            RiffReader {
                r,
                total_len: list_len - 4,
                chunk_len: 0,
                chunk_read: 0,
                padded: false,
            },
        ))
    }

    /// `riff.Reader.Next`: the next chunk's id and length. `None` at the end
    /// of the list.
    fn next(&mut self) -> io::Result<Option<([u8; 4], u32)>> {
        if self.chunk_len != 0 {
            let left = u64::from(self.chunk_len - self.chunk_read);
            let got = io::copy(&mut (&mut *self.r).take(left), &mut io::sink())?;
            if got != left {
                return Err(invalid("riff: short chunk data"));
            }
        }
        if self.padded {
            if self.total_len == 0 {
                return Err(invalid("riff: list subchunk too long"));
            }
            self.total_len -= 1;
            let mut pad = [0u8; 1];
            read_full(self.r, &mut pad).map_err(|_| invalid("riff: missing padding byte"))?;
        }
        if self.total_len == 0 {
            return Ok(None);
        }
        if self.total_len < CHUNK_HEADER_SIZE {
            return Err(invalid("riff: short chunk header"));
        }
        self.total_len -= CHUNK_HEADER_SIZE;
        let mut buf = [0u8; CHUNK_HEADER_SIZE as usize];
        read_full(self.r, &mut buf).map_err(|_| invalid("riff: short chunk header"))?;
        let id = [buf[0], buf[1], buf[2], buf[3]];
        self.chunk_len = u32_le(&buf[4..]);
        if self.chunk_len > self.total_len {
            return Err(invalid("riff: list subchunk too long"));
        }
        self.padded = self.chunk_len & 1 == 1;
        self.chunk_read = 0;
        Ok(Some((id, self.chunk_len)))
    }

    /// Reads `buf` from the current chunk, as a `chunkReader` bounded by the
    /// chunk length does.
    fn read_chunk(&mut self, buf: &mut [u8]) -> io::Result<()> {
        if (buf.len() as u64) > u64::from(self.chunk_len - self.chunk_read) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            ));
        }
        read_full(self.r, buf)?;
        self.chunk_read += buf.len() as u32;
        Ok(())
    }
}

/// `vp8.Decoder.DecodeFrameHeader`: the key frame's width and height; a
/// non-key frame has none.
fn vp8_frame_header(riff: &mut RiffReader<'_>) -> io::Result<(i32, i32)> {
    let mut b = [0u8; 3];
    riff.read_chunk(&mut b)?;
    let key_frame = b[0] & 1 == 0;
    if !key_frame {
        return Ok((0, 0));
    }
    let mut b = [0u8; 7];
    riff.read_chunk(&mut b)?;
    if b[0] != 0x9d || b[1] != 0x01 || b[2] != 0x2a {
        return Err(invalid("vp8: invalid format"));
    }
    let width = i32::from(b[4] & 0x3f) << 8 | i32::from(b[3]);
    let height = i32::from(b[6] & 0x3f) << 8 | i32::from(b[5]);
    Ok((width, height))
}

/// `vp8l.decodeHeader`: the lossless header's width and height, read as
/// little-endian bit fields.
fn vp8l_header(riff: &mut RiffReader<'_>) -> io::Result<(i32, i32)> {
    let mut b = [0u8; 5];
    riff.read_chunk(&mut b)?;
    let bits = u64::from(u32_le(&b[..4])) | u64::from(b[4]) << 32;
    let field = |shift: u32, n: u32| ((bits >> shift) & ((1u64 << n) - 1)) as i32;
    if field(0, 8) != 0x2f {
        return Err(invalid("vp8l: invalid header"));
    }
    let width = field(8, 14) + 1;
    let height = field(22, 14) + 1;
    // Bit 36 is the alpha hint, ignored; the three after it are the version.
    if field(37, 3) != 0 {
        return Err(invalid("vp8l: invalid version"));
    }
    Ok((width, height))
}

/// `webp.DecodeConfig`: the dimensions and color model of a WebP image, from
/// its first VP8X, VP8 or VP8L chunk.
pub fn decode_config(r: &mut dyn Read) -> io::Result<Config> {
    let (form, mut riff) = RiffReader::new(r)?;
    if form != FCC_WEBP {
        return Err(invalid_format());
    }
    loop {
        let Some((chunk_id, chunk_len)) = riff.next()? else {
            return Err(invalid_format());
        };
        match chunk_id {
            FCC_ALPH => return Err(invalid_format()),
            FCC_VP8 => {
                if chunk_len > i32::MAX as u32 {
                    return Err(invalid_format());
                }
                let (width, height) = vp8_frame_header(&mut riff)?;
                return Ok(Config {
                    color_model: Model::Ycbcr,
                    width,
                    height,
                });
            }
            FCC_VP8L => {
                let (width, height) = vp8l_header(&mut riff)?;
                return Ok(Config {
                    color_model: Model::Nrgba,
                    width,
                    height,
                });
            }
            FCC_VP8X => {
                if chunk_len != 10 {
                    return Err(invalid_format());
                }
                let mut buf = [0u8; 10];
                riff.read_chunk(&mut buf)?;
                const ALPHA_BIT: u8 = 1 << 4;
                let want_alpha = buf[0] & ALPHA_BIT != 0;
                let width_minus_one =
                    u32::from(buf[4]) | u32::from(buf[5]) << 8 | u32::from(buf[6]) << 16;
                let height_minus_one =
                    u32::from(buf[7]) | u32::from(buf[8]) << 8 | u32::from(buf[9]) << 16;
                let (w, h) = (
                    u64::from(width_minus_one) + 1,
                    u64::from(height_minus_one) + 1,
                );
                if w * h > (1 << 31) - 1 {
                    // The product of the canvas width and height must fit in
                    // an int.
                    return Err(invalid_format());
                }
                return Ok(Config {
                    color_model: if want_alpha {
                        Model::Nycbcra
                    } else {
                        Model::Ycbcr
                    },
                    width: width_minus_one as i32 + 1,
                    height: height_minus_one as i32 + 1,
                });
            }
            _ => {}
        }
    }
}

static REGISTERED: Once = Once::new();

/// Registers "webp" with `image`, as importing `x/image/webp` does, once.
pub fn register() {
    REGISTERED.call_once(|| {
        image::register_format(
            "webp",
            b"RIFF????WEBPVP8",
            |_| {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "webp: decoding is not supported",
                ))
            },
            decode_config,
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn riff(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let mut body = b"WEBP".to_vec();
        for (id, data) in chunks {
            body.extend_from_slice(*id);
            body.extend_from_slice(&(data.len() as u32).to_le_bytes());
            body.extend_from_slice(data);
            if data.len() % 2 == 1 {
                body.push(0);
            }
        }
        let mut out = b"RIFF".to_vec();
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// A VP8 key frame header for a 3x2 image, as `vp8.Encode` writes one.
    fn vp8_key_frame(width: u16, height: u16) -> Vec<u8> {
        let mut data = vec![0x10, 0x00, 0x00, 0x9d, 0x01, 0x2a];
        data.extend_from_slice(&width.to_le_bytes());
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(&[0; 8]);
        data
    }

    #[test]
    fn lossy_dimensions_come_from_the_frame_header() {
        let image = riff(&[(&FCC_VP8, &vp8_key_frame(3, 2))]);
        let config = decode_config(&mut &image[..]).unwrap();
        assert_eq!((config.width, config.height), (3, 2));
        assert_eq!(config.color_model, Model::Ycbcr);
    }

    #[test]
    fn lossless_dimensions_come_from_the_bit_fields() {
        // 0x2f, then width-1 = 2 in 14 bits, height-1 = 1 in 14 bits.
        let bits: u64 = 0x2f | (2 << 8) | (1 << 22);
        let header = bits.to_le_bytes();
        let image = riff(&[(&FCC_VP8L, &header[..5])]);
        let config = decode_config(&mut &image[..]).unwrap();
        assert_eq!((config.width, config.height), (3, 2));
        assert_eq!(config.color_model, Model::Nrgba);
    }

    #[test]
    fn extended_header_gives_the_canvas() {
        let mut vp8x = [0u8; 10];
        vp8x[0] = 1 << 4;
        vp8x[4] = 2;
        vp8x[7] = 1;
        let image = riff(&[(&FCC_VP8X, &vp8x)]);
        let config = decode_config(&mut &image[..]).unwrap();
        assert_eq!((config.width, config.height), (3, 2));
        assert_eq!(config.color_model, Model::Nycbcra);
    }

    #[test]
    fn malformed_images_are_invalid() {
        for (name, bytes) in [
            ("not riff", b"RIFX\x04\x00\x00\x00WEBP".to_vec()),
            ("not webp", b"RIFF\x04\x00\x00\x00WAVE".to_vec()),
            ("no chunks", riff(&[])),
            (
                "bad sync code",
                riff(&[(&FCC_VP8, &[0x10, 0, 0, 0, 1, 0x2a, 3, 0, 2, 0])]),
            ),
            (
                "alpha before vp8x",
                riff(&[(&FCC_ALPH, &[0]), (&FCC_VP8, &vp8_key_frame(3, 2))]),
            ),
            ("short vp8x", riff(&[(&FCC_VP8X, &[0; 9])])),
        ] {
            assert!(decode_config(&mut &bytes[..]).is_err(), "{name}");
        }
    }

    #[test]
    fn registers_with_image() {
        register();
        let image = riff(&[(&FCC_VP8, &vp8_key_frame(3, 2))]);
        let (config, format) = image::decode_config(&image[..]).unwrap();
        assert_eq!(
            (format.as_str(), config.width, config.height),
            ("webp", 3, 2)
        );
    }
}
