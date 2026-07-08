//! Thumbnail generation for image and video files, matching the Java
//! `JavaImageThumbnailer` and `FFmpegThumbnailer` algorithms.

const THUMBNAIL_SIZE: u32 = 400;
const THUMBNAIL_DOWNSCALE: u32 = 200;
const THUMBNAIL_MAX_BYTES: usize = 100 * 1024;

/// A generated thumbnail (mime type + raw bytes), matching `Thumbnail` in Java.
#[derive(Debug, Clone)]
pub struct Thumbnail {
    pub mime_type: String,
    pub data: Vec<u8>,
}

impl Thumbnail {
    pub fn new(mime_type: impl Into<String>, data: Vec<u8>) -> Self {
        Thumbnail { mime_type: mime_type.into(), data }
    }

    /// Convert to the `(mime_type, bytes)` tuple used by the upload API.
    pub fn into_tuple(self) -> (String, Vec<u8>) {
        (self.mime_type, self.data)
    }

    /// Wrap a tuple from the upload API.
    pub fn from_tuple(t: (String, Vec<u8>)) -> Self {
        Thumbnail { mime_type: t.0, data: t.1 }
    }
}

/// Attempt to generate a thumbnail for the given file data and MIME type.
/// Handles images (via `image` + `webp`) and videos (via `ffmpeg` CLI).
/// Returns `None` when the MIME type isn't supported or generation fails.
#[cfg(feature = "thumbnails")]
pub fn generate_thumbnail(data: &[u8], mime_type: &str) -> Option<Thumbnail> {
    if mime_type.starts_with("image/") && mime_type != "image/svg+xml" {
        generate_image_thumbnail(data)
    } else if mime_type.starts_with("video/") {
        generate_video_thumbnail(data)
    } else {
        None
    }
}

// ---- image thumbnails ----------------------------------------------------

/// Center-cropped square webp thumbnail of `size`×`size` (mirrors the Peergos
/// JavaImageThumbnailer: scale the short edge to `size`, crop the long edge).
#[cfg(feature = "thumbnails")]
fn center_crop_webp(img: &image::DynamicImage, size: u32) -> Vec<u8> {
    use image::imageops::FilterType;
    let (w, h) = (img.width(), img.height());
    let tall = h > w;
    let canvas_w = if tall { size } else { w * size / h };
    let canvas_h = if tall { h * size / w } else { size };
    let resized = img.resize_exact(canvas_w, canvas_h, FilterType::Triangle);
    let x = if tall { 0 } else { (canvas_w - size) / 2 };
    let y = if tall { (canvas_h - size) / 2 } else { 0 };
    let rgba = resized.crop_imm(x, y, size, size).to_rgba8();
    webp::Encoder::from_rgba(rgba.as_raw(), size, size).encode(80.0).to_vec()
}

/// Generate a 400×400 WebP thumbnail from image bytes. Downscales to 200×200
/// if the result exceeds 100 KiB (matching the server-side limit).
#[cfg(feature = "thumbnails")]
pub fn generate_image_thumbnail(data: &[u8]) -> Option<Thumbnail> {
    let img = image::load_from_memory(data).ok()?;
    let big = center_crop_webp(&img, THUMBNAIL_SIZE);
    let out = if big.len() > THUMBNAIL_MAX_BYTES {
        center_crop_webp(&img, THUMBNAIL_DOWNSCALE)
    } else {
        big
    };
    Some(Thumbnail::new("image/webp", out))
}

// ---- video thumbnails ----------------------------------------------------

/// Extract a video frame via the `ffmpeg` CLI and generate a WebP thumbnail.
/// Returns `None` if ffmpeg is not installed or the video can't be decoded.
#[cfg(feature = "thumbnails")]
pub fn generate_video_thumbnail(data: &[u8]) -> Option<Thumbnail> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Write video bytes to a temp file so ffmpeg can seek for fast -ss.
    let mut tmp = tempfile::NamedTempFile::new().ok()?;
    tmp.write_all(data).ok()?;
    let tmp_path = tmp.path().to_owned();

    let output = Command::new("ffmpeg")
        .args([
            "-y",
            "-ss", "00:00:01",
            "-i", &tmp_path.to_string_lossy(),
            "-vframes", "1",
            "-f", "image2pipe",
            "-vcodec", "png",
            "pipe:1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    // Temp file is closed (and deleted) when `tmp` drops.

    if !output.status.success() || output.stdout.is_empty() {
        return None;
    }
    generate_image_thumbnail(&output.stdout)
}
