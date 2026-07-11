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

/// Seek points (seconds) tried in order when picking a video frame. We advance
/// past mostly-black/white frames (intros, fades, title cards) until we find one
/// with real content.
#[cfg(feature = "thumbnails")]
const VIDEO_SEEK_SECONDS: &[u32] = &[1, 3, 7, 15, 30, 60, 120, 300, 600];

/// Fraction of near-black/near-white pixels above which a frame is considered
/// uninteresting (a fade, title card, etc.).
#[cfg(feature = "thumbnails")]
const EXTREME_PIXEL_FRACTION: f64 = 0.90;

/// Extract a video frame via the `ffmpeg` CLI and generate a WebP thumbnail.
/// Seeks past mostly-black/white frames so the thumbnail shows real content.
/// Returns `None` if ffmpeg is not installed or the video can't be decoded.
#[cfg(feature = "thumbnails")]
pub fn generate_video_thumbnail(data: &[u8]) -> Option<Thumbnail> {
    use std::io::Write;

    // Write video bytes to a temp file so ffmpeg can seek for fast -ss.
    let mut tmp = tempfile::NamedTempFile::new().ok()?;
    tmp.write_all(data).ok()?;
    let tmp_path = tmp.path().to_owned();

    let mut fallback: Option<Vec<u8>> = None;
    for &secs in VIDEO_SEEK_SECONDS {
        let png = match extract_video_frame(&tmp_path, secs) {
            Some(p) => p,
            None => continue, // seek past the end (or a decode hiccup) — try the next
        };
        // Remember the first decodable frame as a fallback if everything is extreme.
        if fallback.is_none() {
            fallback = Some(png.clone());
        }
        if let Ok(img) = image::load_from_memory(&png) {
            if !mostly_black_or_white(&img) {
                return generate_image_thumbnail(&png);
            }
        }
    }
    // Every candidate was mostly black/white (or undecodable): use the first frame.
    fallback.and_then(|png| generate_image_thumbnail(&png))
}

/// Extract a single PNG frame at `seconds` into the video. `None` if ffmpeg fails
/// or the seek is past the end (empty output).
#[cfg(feature = "thumbnails")]
fn extract_video_frame(path: &std::path::Path, seconds: u32) -> Option<Vec<u8>> {
    use std::process::{Command, Stdio};
    let output = Command::new("ffmpeg")
        .args([
            "-y",
            "-ss", &format!("{seconds}"),
            "-i", &path.to_string_lossy(),
            "-frames:v", "1",
            "-f", "image2pipe",
            "-vcodec", "png",
            "pipe:1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.is_empty() {
        return None;
    }
    Some(output.stdout)
}

/// True if the frame is dominated by near-black/near-white pixels (a fade or
/// title card) and so makes a poor thumbnail.
#[cfg(feature = "thumbnails")]
fn mostly_black_or_white(img: &image::DynamicImage) -> bool {
    // Downscale first so the scan is cheap and averages out sub-pixel noise.
    use image::imageops::FilterType;
    let small = img.resize(64, 64, FilterType::Triangle).to_rgb8();
    let total = (small.width() * small.height()) as f64;
    if total == 0.0 {
        return true;
    }
    let mut extreme = 0u64;
    for p in small.pixels() {
        let [r, g, b] = p.0;
        let luma = 0.299 * r as f64 + 0.587 * g as f64 + 0.114 * b as f64;
        if luma < 18.0 || luma > 237.0 {
            extreme += 1;
        }
    }
    (extreme as f64 / total) > EXTREME_PIXEL_FRACTION
}

#[cfg(all(test, feature = "thumbnails"))]
mod tests {
    use super::*;

    fn solid(rgb: [u8; 3]) -> image::DynamicImage {
        image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(128, 128, image::Rgb(rgb)))
    }

    #[test]
    fn black_and_white_frames_are_extreme() {
        assert!(mostly_black_or_white(&solid([0, 0, 0])));
        assert!(mostly_black_or_white(&solid([255, 255, 255])));
        // A near-black fade is still extreme.
        assert!(mostly_black_or_white(&solid([8, 8, 8])));
    }

    #[test]
    fn content_frames_are_not_extreme() {
        // A flat mid-tone.
        assert!(!mostly_black_or_white(&solid([128, 120, 110])));
        // A colourful gradient.
        let grad = image::RgbImage::from_fn(128, 128, |x, _| image::Rgb([(x * 2) as u8, 100, 150]));
        assert!(!mostly_black_or_white(&image::DynamicImage::ImageRgb8(grad)));
    }

    #[test]
    fn a_little_content_on_black_is_enough() {
        // 80% black, 20% mid-tone: below the 90% threshold, so it's usable.
        let img = image::RgbImage::from_fn(100, 100, |_, y| {
            if y < 80 { image::Rgb([0, 0, 0]) } else { image::Rgb([120, 120, 120]) }
        });
        assert!(!mostly_black_or_white(&image::DynamicImage::ImageRgb8(img)));
    }
}
