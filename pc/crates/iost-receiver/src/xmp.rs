//! XMP sidecars for move jobs (ARCHITECTURE §2.8, PROTOCOL Δ18): PhotoKit's date, location and
//! favourite, which may differ from the original's EXIF ("Adjust Date & Time / Location").
//! Generated from numbers only; nothing the phone sends as text reaches the file (THREAT_MODEL N8).

use std::io::{self, Write};
use std::path::Path;

use iost_proto::msg::{Asset, Loc};
use sha2::{Digest, Sha256};

use crate::{crash, fsio, naming};

/// The meta the move guard compares (PROTOCOL §6.4): rounded like the fingerprint.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Meta {
    pub created_ms: i64,
    pub tz_min: i32,
    pub fav: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loc: Option<Loc>,
}

impl Meta {
    pub fn of(a: &Asset) -> Self {
        Meta { created_ms: a.created_ms, tz_min: a.tz_min, fav: a.fav, loc: a.loc.clone() }
    }

    pub fn from_json(s: &str) -> Option<Self> {
        serde_json::from_str(s).ok()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("meta serializes")
    }

    /// Comparison key: `created_ms`, `fav`, lat/lon to 1e-7°, alt to 0.01 m. `tz_min` only
    /// affects how the date is written, so it is part of the XMP hash below, not of this key.
    pub fn key(&self) -> String {
        let loc = match &self.loc {
            None => "-".to_string(),
            Some(l) => format!(
                "{:.7},{:.7},{}",
                l.lat,
                l.lon,
                l.alt.map_or("-".to_string(), |a| format!("{a:.2}"))
            ),
        };
        format!("{}|{}|{loc}", self.created_ms, u8::from(self.fav))
    }

    /// Identifies the exact XMP content (stored as `assets.xmp_meta_hash`).
    pub fn xmp_hash(&self) -> String {
        hex::encode(Sha256::digest(format!("{}|{}", self.key(), self.tz_min)))
    }
}

/// XMP GPS coordinate: `DDD,MM.mmmmmmmR`.
fn gps(v: f64, pos: char, neg: char) -> String {
    let dir = if v < 0.0 { neg } else { pos };
    let v = v.abs();
    let deg = v.trunc();
    format!("{},{:.7}{dir}", deg as u32, (v - deg) * 60.0)
}

pub fn render(m: &Meta) -> String {
    let (y, mo, d, h, mi, s) = naming::local_parts(m.created_ms, m.tz_min);
    let tz = m.tz_min.unsigned_abs();
    let offset = format!("{}{:02}:{:02}", if m.tz_min < 0 { '-' } else { '+' }, tz / 60, tz % 60);
    let date = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}{offset}");
    let mut props = vec![
        format!("   exif:DateTimeOriginal=\"{date}\""),
        format!("   exif:OffsetTimeOriginal=\"{offset}\""),
        format!("   xmp:CreateDate=\"{date}\""),
    ];
    if m.fav {
        props.push("   xmp:Rating=\"5\"".into());
    }
    if let Some(l) = &m.loc {
        props.push(format!("   exif:GPSLatitude=\"{}\"", gps(l.lat, 'N', 'S')));
        props.push(format!("   exif:GPSLongitude=\"{}\"", gps(l.lon, 'E', 'W')));
        if let Some(a) = l.alt {
            let cm = (a.abs() * 100.0).round() as u64;
            props.push(format!("   exif:GPSAltitude=\"{cm}/100\""));
            props.push(format!("   exif:GPSAltitudeRef=\"{}\"", u8::from(a < 0.0)));
        }
    }
    format!(
        "<?xpacket begin=\"\u{feff}\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n\
         <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"iostransfer\">\n\
         \x20<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n\
         \x20 <rdf:Description rdf:about=\"\"\n\
         \x20  xmlns:exif=\"http://ns.adobe.com/exif/1.0/\"\n\
         \x20  xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"\n\
         {}/>\n\
         \x20</rdf:RDF>\n\
         </x:xmpmeta>\n\
         <?xpacket end=\"w\"?>\n",
        props.join("\n")
    )
}

/// `.<base>.xmp.tmp` next to the final `<base>.xmp`.
pub fn tmp_name(base: &str) -> String {
    format!(".{base}.xmp.tmp")
}

/// Write `<base_rel>.xmp` durably: tmp → fsync → rename (replace) → fsync dir.
pub fn write(dest: &Path, base_rel: &str, m: &Meta) -> io::Result<()> {
    let (dir_rel, base) = base_rel.rsplit_once('/').expect("base_rel has a directory");
    let dir = fsio::ensure_dir(dest, dir_rel)?;
    let tmp = dir.join(tmp_name(base));
    let fin = dir.join(format!("{base}.xmp"));
    fsio::remove_if_exists(&tmp)?;
    let mut f = fsio::create_part(&tmp)?;
    f.write_all(render(m).as_bytes())?;
    f.sync_all()?;
    drop(f);
    crash::at("X1", "");
    fsio::rename_replace(&tmp, &fin)?;
    fsio::fsync_dir(&dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(fav: bool, loc: Option<Loc>) -> Meta {
        Meta { created_ms: 1_710_411_322_000, tz_min: 60, fav, loc }
    }

    #[test]
    fn renders_date_rating_and_gps() {
        let x = render(&meta(true, Some(Loc { lat: 48.8583701, lon: -2.2944813, alt: Some(35.2) })));
        assert!(x.contains("exif:DateTimeOriginal=\"2024-03-14T11:15:22+01:00\""), "{x}");
        assert!(x.contains("xmp:Rating=\"5\""));
        assert!(x.contains("exif:GPSLatitude=\"48,51.5022060N\""), "{x}");
        assert!(x.contains("exif:GPSLongitude=\"2,17.6688780W\""), "{x}");
        assert!(x.contains("exif:GPSAltitude=\"3520/100\""));
        let plain = render(&meta(false, None));
        assert!(!plain.contains("Rating") && !plain.contains("GPS"));
    }

    #[test]
    fn negative_offsets_and_keys() {
        let m = Meta { created_ms: 0, tz_min: -330, fav: false, loc: None };
        assert!(render(&m).contains("\"1969-12-31T18:30:00-05:30\""));
        let a = meta(false, Some(Loc { lat: 1.00000001, lon: 2.0, alt: None }));
        let b = meta(false, Some(Loc { lat: 1.00000004, lon: 2.0, alt: None }));
        assert_eq!(a.key(), b.key(), "differences below 1e-7° are equal");
        assert_ne!(a.key(), meta(true, a.loc.clone()).key());
    }
}
