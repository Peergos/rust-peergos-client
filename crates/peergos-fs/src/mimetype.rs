//! MIME-type detection, a faithful port of `peergos.shared.user.fs.MimeTypes`.
//! Detection is content-based (magic bytes over the first
//! [`HEADER_BYTES_TO_IDENTIFY_MIME_TYPE`] bytes) with filename-extension
//! tie-breakers, falling back to the prefix-tolerant UTF-8 check for text.

/// Bytes of the file header used for detection.
pub const HEADER_BYTES_TO_IDENTIFY_MIME_TYPE: usize = 40;

// Magic byte prefixes (all values fit in a byte).
const MID: &[u8] = b"MThd";
const ID3: &[u8] = b"ID3";
const MP3: &[u8] = &[0xff, 0xfb];
const MP3_2: &[u8] = &[0xff, 0xfa];
const RIFF: &[u8] = b"RIFF";
const WAV_2: &[u8] = b"WAVE";
const FLAC: &[u8] = b"fLaC";
const OPUS: &[u8] = b"OpusHead";
const OGG_FLAC: &[u8] = &[0x7f, b'F', b'L', b'A', b'C'];
const VORBIS: &[u8] = &[1, b'v', b'o', b'r', b'b', b'i', b's'];
const SPEEX: &[u8] = &[b'S', b'p', b'e', b'e', b'x', 0x20, 0x20, 0x20];

const MP4: &[u8] = b"ftyp";
const ISO2: &[u8] = b"iso2";
const ISOM: &[u8] = b"isom";
const DASH: &[u8] = b"dash";
const MP41: &[u8] = b"mp41";
const MP42: &[u8] = b"mp42";
const M4V: &[u8] = b"M4V ";
const AVIF: &[u8] = b"avif";
const HEIC: &[u8] = b"heic";
const AVC1: &[u8] = b"avc1";
const M4A: &[u8] = b"M4A ";
const QT: &[u8] = b"qt  ";
const QT2: &[u8] = b"pnot";
const QT3: &[u8] = b"moov";
const QT4: &[u8] = b"mdat";
const THREEGP: &[u8] = b"3gp";

const FLV: &[u8] = b"FLV";
const FORM: &[u8] = b"FORM";
const AIFF: &[u8] = b"AIFF";
const AVI: &[u8] = b"AVI ";
const OGG: &[u8] = &[b'O', b'g', b'g', b'S', 0, 2];
const THEORA: &[u8] = &[0x80, b't', b'h', b'e', b'o', b'r', b'a'];
const FISHEAD: &[u8] = &[b'f', b'i', b's', b'h', b'e', b'a', b'd', 0];
const OGM_VIDEO: &[u8] = &[1, b'v', b'i', b'd', b'e', b'o', 0, 0, 0];
const WEBM: &[u8] = b"webm";
const MATROSKA_START: &[u8] = &[0x1a, 0x45, 0xdf, 0xa3];

const ICO: &[u8] = &[0, 0, 1, 0];
const CUR: &[u8] = &[0, 0, 2, 0];
const BMP: &[u8] = b"BM";
const GIF: &[u8] = b"GIF";
const JPEG: &[u8] = &[255, 216];
const TIFF1: &[u8] = &[b'I', b'I', 0x2A, 0];
const TIFF2: &[u8] = &[b'M', b'M', 0, 0x2A];
const PNG: &[u8] = &[137, b'P', b'N', b'G', 13, 10, 26, 10];
const WEBP: &[u8] = b"WEBP";
const JPEGXL: &[u8] = &[0xff, 0x0a];
const JPEGXL2: &[u8] = &[0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A];

const PDF: &[u8] = &[0x25, b'P', b'D', b'F'];
const PS: &[u8] = b"%!PS-Adobe-";
const ZIP: &[u8] = &[b'P', b'K', 3, 4];
const GZIP: &[u8] = &[0x1f, 0x8b, 0x08];
const RAR: &[u8] = &[b'R', b'a', b'r', b'!', 0x1a, 0x07];
const WASM: &[u8] = &[0, b'a', b's', b'm'];

const ICS: &[u8] = b"BEGIN:VCALENDAR";
const VCF: &[u8] = b"BEGIN:VCARD";
const XML: &[u8] = b"<?xml";
const SVG: &[u8] = b"<svg ";
const WOFF: &[u8] = b"wOFF";
const WOFF2: &[u8] = b"wOF2";
const OTF: &[u8] = b"OTTO";
const TTF: &[u8] = &[0, 1, 0, 0];

const CBOR_PEERGOS_POST: &[u8] = &[0x82, 17];
const CBOR_PEERGOS_IDENTITY_PROOF: &[u8] = &[0x82, 0x18, 24];
const CBOR_PEERGOS_EMAIL: &[u8] = &[0x82, 0x18, 18];
pub const PEERGOS_POST: &str = "application/vnd.peergos-post";
pub const PEERGOS_IDENTITY: &str = "application/vnd.peergos-identity-proof";
pub const PEERGOS_EMAIL: &str = "application/vnd.peergos-email";

/// `MimeTypes.equalArrays(a, offset, target)`.
fn matches(a: &[u8], offset: usize, target: &[u8]) -> bool {
    if offset + target.len() > a.len() {
        return false;
    }
    a[offset..offset + target.len()] == *target
}

fn matches0(a: &[u8], target: &[u8]) -> bool {
    matches(a, 0, target)
}

/// `text/<ext-mapping>` extensions (`MimeTypes.TEXT_MIMETYPES`).
fn text_mimetype(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "md" => "md",
        "csv" => "csv",
        "edn" => "x-clojure",
        "excalidraw" => "application/vnd.excalidraw+json",
        "xml" => "xml",
        "asp" => "asp",
        "rt" => "richtext",
        "rtf" => "rtf",
        "rtx" => "richtext",
        "java" => "x-java-source",
        "mjs" => "javascript",
        "gv" => "vnd.graphviz",
        "f" => "x-fortran",
        "s" => "x-asm",
        "p" => "x-pascal",
        "yaml" => "yaml",
        "c" => "x-c",
        _ => return None,
    })
}

/// Detect the MIME type from the file header `start` and its `filename`
/// (`MimeTypes.calculateMimeType`).
pub fn calculate_mime_type(start: &[u8], filename: &str) -> String {
    let s = |v: &str| v.to_string();

    if matches0(start, BMP) {
        return s("image/bmp");
    }
    if matches0(start, GIF) {
        return s("image/gif");
    }
    if matches0(start, PNG) {
        if filename.ends_with(".ico") {
            return s("image/vnd.microsoft.icon");
        }
        return s("image/png");
    }
    if matches0(start, JPEG) {
        return s("image/jpg");
    }
    if matches0(start, ICO) {
        return s("image/x-icon");
    }
    if matches0(start, CUR) {
        return s("image/x-icon");
    }
    if matches0(start, RIFF) && matches(start, 8, WEBP) {
        return s("image/webp");
    }
    if matches0(start, JPEGXL) || matches0(start, JPEGXL2) {
        return s("image/jxl");
    }
    if matches0(start, TIFF1) || matches0(start, TIFF2) {
        return s("image/tiff");
    }

    if !start.is_empty() && start[0] == 0 && matches(start, 4, MP4) {
        if matches(start, 8, ISO2)
            || matches(start, 8, ISOM)
            || matches(start, 8, DASH)
            || matches(start, 8, MP42)
            || matches(start, 8, MP41)
            || matches(start, 16, ISOM)
        {
            return s("video/mp4");
        }
        if matches(start, 8, M4V) {
            return s("video/m4v");
        }
        if matches(start, 8, AVIF) {
            return s("image/avif");
        }
        if matches(start, 8, HEIC) {
            return s("image/heic");
        }
        if matches(start, 8, M4A) {
            return s("audio/mp4");
        }
        if matches(start, 8, AVC1) {
            return s("video/h264");
        }
        if matches(start, 8, QT) {
            return s("video/quicktime");
        }
        if matches(start, 8, THREEGP) {
            return s("video/3gpp");
        }
        return s("video/mp4");
    }
    if matches(start, 4, QT2) || matches(start, 4, QT3) || matches(start, 4, QT4) {
        return s("video/quicktime");
    }
    if matches(start, 24, WEBM) {
        return s("video/webm");
    }
    if matches0(start, OGG)
        && (matches(start, 28, THEORA) || matches(start, 28, FISHEAD) || matches(start, 28, OGM_VIDEO))
    {
        return s("video/ogg");
    }
    if matches0(start, MATROSKA_START) {
        return s("video/x-matroska");
    }
    if matches0(start, FLV) {
        return s("video/x-flv");
    }
    if matches(start, 8, AVI) {
        return s("video/avi");
    }

    if matches0(start, MID) {
        return s("audio/midi");
    }
    if matches0(start, ID3) || matches0(start, MP3) || matches0(start, MP3_2) {
        return s("audio/mpeg");
    }
    if matches0(start, FLAC) {
        return s("audio/flac");
    }
    if matches0(start, OGG)
        && (matches(start, 28, OPUS)
            || matches(start, 28, OGG_FLAC)
            || matches(start, 28, VORBIS)
            || matches(start, 28, SPEEX))
    {
        return s("audio/ogg");
    }
    if matches0(start, RIFF) && matches(start, 8, WAV_2) {
        return s("audio/wav");
    }
    if matches0(start, FORM) && matches(start, 8, AIFF) {
        return s("audio/aiff");
    }

    if matches0(start, PDF) {
        return s("application/pdf");
    }
    if matches0(start, PS) {
        return s("application/postscript");
    }
    if matches0(start, WASM) {
        return s("application/wasm");
    }

    if matches0(start, ZIP) {
        if filename.ends_with(".jar") {
            return s("application/java-archive");
        }
        if filename.ends_with(".epub") {
            return s("application/epub+zip");
        }
        if filename.ends_with(".pptx") {
            return s("application/vnd.openxmlformats-officedocument.presentationml.presentation");
        }
        if filename.ends_with(".docx") {
            return s("application/vnd.openxmlformats-officedocument.wordprocessingml.document");
        }
        if filename.ends_with(".xlsx") {
            return s("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
        }
        if filename.ends_with(".odt") {
            return s("application/vnd.oasis.opendocument.text");
        }
        if filename.ends_with(".ods") {
            return s("application/vnd.oasis.opendocument.spreadsheet");
        }
        if filename.ends_with(".odp") {
            return s("application/vnd.oasis.opendocument.presentation");
        }
        if filename.ends_with(".apk") {
            return s("application/vnd.android.package-archive");
        }
        return s("application/zip");
    }

    if matches0(start, GZIP) {
        return s("application/x-gzip");
    }
    if matches0(start, RAR) {
        return s("application/x-rar-compressed");
    }

    if matches0(start, WOFF) {
        return s("font/woff");
    }
    if matches0(start, WOFF2) {
        return s("font/woff2");
    }
    if matches0(start, OTF) {
        return s("font/otf");
    }
    if matches0(start, TTF) {
        return s("font/ttf");
    }

    if matches0(start, CBOR_PEERGOS_POST) {
        return s(PEERGOS_POST);
    }
    if matches0(start, CBOR_PEERGOS_IDENTITY_PROOF) {
        return s(PEERGOS_IDENTITY);
    }
    if matches0(start, CBOR_PEERGOS_EMAIL) {
        return s(PEERGOS_EMAIL);
    }

    if valid_utf8(start) {
        if filename.ends_with(".ics") && matches0(start, ICS) {
            return s("text/calendar");
        }
        if filename.ends_with(".vcf") && matches0(start, VCF) {
            return s("text/vcard");
        }
        if filename.ends_with(".html") {
            return s("text/html");
        }
        if filename.ends_with(".css") {
            return s("text/css");
        }
        if filename.ends_with(".js") {
            return s("text/javascript");
        }
        if filename.ends_with(".svg") && (matches0(start, XML) || matches0(start, SVG)) {
            return s("image/svg+xml");
        }
        if filename.ends_with(".json") {
            return s("application/json");
        }
        if let Some(dot) = filename.rfind('.') {
            let ext = &filename[dot + 1..];
            if let Some(mapped) = text_mimetype(ext) {
                return format!("text/{mapped}");
            }
            if ext == "c9r" || ext == "c9s" || ext == "bkup" || ext == "cryptomator" {
                return s("application/vnd.cryptomator.encrypted");
            }
        }
        let prefix = String::from_utf8_lossy(start).trim().to_lowercase();
        if prefix.contains("html>") || prefix.contains("<html") {
            return s("text/html");
        }
        return s("text/plain");
    }
    s("application/octet-stream")
}

fn is_continuation_byte(b: u8) -> bool {
    (b & 0xc0) == 0x80
}

/// `MimeTypes.validUtf8` — a prefix-tolerant UTF-8 validator (tolerates a
/// truncated final multi-byte char, since the input is only a header prefix).
fn valid_utf8(data: &[u8]) -> bool {
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if (b as u32) < 0x80 {
            i += 1;
            continue; // ASCII
        }
        let len = b.leading_ones() as usize;
        if !(2..=4).contains(&len) {
            return false;
        }
        if i + len > data.len() {
            return data[i + 1..].iter().all(|&x| is_continuation_byte(x));
        }
        for x in 1..len {
            if !is_continuation_byte(data[i + x]) {
                return false;
            }
        }
        let val: u32 = match len {
            2 => {
                let v = (((b & 0x1f) as u32) << 6) | (data[i + 1] & 0x3f) as u32;
                if v <= 0x7f {
                    return false;
                }
                v
            }
            3 => {
                let v = (((b & 0xf) as u32) << 12)
                    | (((data[i + 1] & 0x3f) as u32) << 6)
                    | (data[i + 2] & 0x3f) as u32;
                if v <= 0x7ff {
                    return false;
                }
                v
            }
            _ => {
                let v = (((b & 0x7) as u32) << 18)
                    | (((data[i + 1] & 0x3f) as u32) << 12)
                    | (((data[i + 2] & 0x3f) as u32) << 6)
                    | (data[i + 3] & 0x3f) as u32;
                if v <= 0xffff {
                    return false;
                }
                v
            }
        };
        if val > 0x10ffff {
            return false;
        }
        if val > 0xd800 && val <= 0xdfff {
            return false;
        }
        i += len;
    }
    true
}
