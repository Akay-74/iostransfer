//! Output paths (ARCHITECTURE §4.3, THREAT_MODEL N6). Every component that comes from the phone
//! goes through [`component`]; extensions come only from a UTI allowlist.

use iost_proto::msg::{Asset, ResDesc};

use crate::text::is_deceptive;

const MAX_COMPONENT: usize = 100;
const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1",
    "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// A safe single path component: no separators, no Windows-forbidden or deceptive characters, no
/// leading dot (hidden / `..`), no trailing dots or spaces, no reserved device names.
pub fn component(raw: &str) -> String {
    let mut out = String::new();
    for c in raw.chars() {
        if is_deceptive(c) || "<>:\"/\\|?*".contains(c) {
            continue;
        }
        if out.len() + c.len_utf8() > MAX_COMPONENT {
            break;
        }
        out.push(c);
    }
    let trimmed = out.trim_end_matches(['.', ' ']).trim_start_matches(['.', ' ']);
    let mut out = trimmed.to_string();
    let stem = out.split('.').next().unwrap_or("").to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        out.insert(0, '_');
    }
    if out.is_empty() { "_".into() } else { out }
}

/// File extension for a UTI. Unknown types get `.bin`: the phone never picks an extension.
pub fn extension(uti: &str) -> &'static str {
    match uti {
        "public.heic" => "HEIC",
        "public.heif" => "HEIF",
        "public.jpeg" => "JPG",
        "public.png" => "PNG",
        "public.tiff" => "TIF",
        "com.compuserve.gif" => "GIF",
        "org.webmproject.webp" => "WEBP",
        "com.adobe.raw-image" | "com.apple.raw-image" => "DNG",
        "com.apple.quicktime-movie" => "MOV",
        "public.mpeg-4" => "MP4",
        "public.mpeg-4-audio" | "com.apple.m4a-audio" => "M4A",
        "com.apple.photos.adjustment" | "com.apple.adjustment" => "AAE",
        "public.xml" | "com.apple.property-list" => "plist",
        _ => "bin",
    }
}

/// Suffix that keeps the resources of one asset apart under a shared base name.
fn suffix(ty: &str) -> String {
    match ty {
        "photo" | "video" | "paired_video" | "alternate_photo" | "adjustment_data" | "audio" => String::new(),
        "full_size_photo" | "full_size_video" | "full_size_paired_video" => "_edited".into(),
        "adjustment_base_photo" | "adjustment_base_video" | "adjustment_base_paired_video" => "_base".into(),
        other => format!("_{}", component(other)),
    }
}

/// Phone-local wall time of the asset: (year, month, "YYYYMMDD_HHMMSS").
pub fn local_time(created_ms: i64, tz_min: i32) -> (i64, u32, String) {
    let secs = (created_ms + tz_min as i64 * 60_000).div_euclid(1000);
    let (days, sod) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    let stamp = format!("{y:04}{m:02}{d:02}_{:02}{:02}{:02}", sod / 3600, sod % 3600 / 60, sod % 60);
    (y, m, stamp)
}

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian (H. Hinnant).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// The resource whose original filename names the asset: the first original photo/video.
fn primary(asset: &Asset) -> Option<&ResDesc> {
    asset
        .res
        .iter()
        .find(|r| matches!(r.ty.as_str(), "photo" | "video"))
        .or_else(|| asset.res.first())
}

/// Relative directory and unsuffixed base name for an asset, `/`-separated.
pub fn base_candidate(device_name: &str, asset: &Asset) -> (String, String) {
    let (y, m, stamp) = local_time(asset.created_ms, asset.tz_min);
    let section = if asset.kind == "video" { "Videos" } else { "Photos" };
    let dir = format!("{}/{section}/{y:04}/{m:02}", component(device_name));
    let stem = primary(asset).map(|r| r.name.rsplit_once('.').map_or(r.name.as_str(), |(s, _)| s)).unwrap_or("asset");
    (dir, format!("{stamp}_{}", component(stem)))
}

/// File name of one resource under the asset's base (`base_rel` = `dir/base`).
pub fn resource_file(base: &str, desc: &ResDesc, all: &[ResDesc]) -> String {
    let n: usize = desc.key.rsplit_once('#').and_then(|(_, n)| n.parse().ok()).unwrap_or(0);
    let mut name = format!("{base}{}", suffix(&desc.ty));
    if n > 0 {
        name.push_str(&format!("_{n}"));
    }
    let ext = extension(&desc.uti);
    // Two resources of one asset must never share a name (e.g. RAW+JPEG where both are JPEG).
    let clash = all.iter().any(|o| {
        o.key != desc.key && suffix(&o.ty) == suffix(&desc.ty) && extension(&o.uti) == ext && o.key < desc.key
    });
    if clash {
        name.push_str(&format!("_{}", component(&desc.ty)));
    }
    format!("{name}.{ext}")
}

/// `.part` file next to a final file.
pub fn part_name(final_name: &str) -> String {
    format!(".{final_name}.part")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(key: &str, ty: &str, uti: &str, name: &str) -> ResDesc {
        ResDesc { key: key.into(), ty: ty.into(), uti: uti.into(), name: name.into(), size: None }
    }

    #[test]
    fn components_are_safe() {
        assert_eq!(component("../../etc/passwd"), "etcpasswd");
        assert_eq!(component("..."), "_");
        assert_eq!(component("CON"), "_CON");
        assert_eq!(component("con.txt"), "_con.txt");
        assert_eq!(component("a<b>c:d|e?f*g\"h"), "abcdefgh");
        assert_eq!(component("Ana's iPhone. "), "Ana's iPhone");
        assert_eq!(component("x\u{202E}y"), "xy");
        assert!(component(&"é".repeat(80)).len() <= MAX_COMPONENT);
    }

    #[test]
    fn local_time_matches_oracle() {
        assert_eq!(local_time(1_710_411_322_000, 60), (2024, 3, "20240314_111522".into()));
        assert_eq!(local_time(0, 0).2, "19700101_000000");
        assert_eq!(local_time(951_782_400_000, 0).2, "20000229_000000"); // leap day
        assert_eq!(local_time(-1000, 0).2, "19691231_235959");
    }

    #[test]
    fn resource_names() {
        let all = vec![
            res("photo#0", "photo", "public.heic", "IMG_0003.HEIC"),
            res("full_size_photo#0", "full_size_photo", "public.jpeg", "FullSizeRender.jpg"),
            res("adjustment_data#0", "adjustment_data", "com.apple.photos.adjustment", "IMG_0003.AAE"),
        ];
        let b = "20240314_111522_IMG_0003";
        assert_eq!(resource_file(b, &all[0], &all), "20240314_111522_IMG_0003.HEIC");
        assert_eq!(resource_file(b, &all[1], &all), "20240314_111522_IMG_0003_edited.JPG");
        assert_eq!(resource_file(b, &all[2], &all), "20240314_111522_IMG_0003.AAE");
        let raw = vec![res("photo#0", "photo", "public.jpeg", "a.JPG"), res("alternate_photo#0", "alternate_photo", "public.jpeg", "a.JPG")];
        assert_ne!(resource_file(b, &raw[0], &raw), resource_file(b, &raw[1], &raw));
        assert_eq!(resource_file(b, &res("x#0", "photo", "evil/../../x", "a"), &[]), format!("{b}.bin"));
    }
}
