use serde::{Deserialize, Serialize};

const MAX_ANDROID_VERSION: u8 = 16;

struct DeviceProfile {
    manufacturer: &'static str,
    device_model: &'static str,
    screen_resolution: &'static str,
    total_ram: &'static str,
    min_android: u8,
}

const DEVICE_PROFILES: &[DeviceProfile] = &[
    // Google Pixel
    DeviceProfile {
        manufacturer: "Google",
        device_model: "Pixel 6",
        screen_resolution: "2400x1080",
        total_ram: "8026152960",
        min_android: 12,
    },
    DeviceProfile {
        manufacturer: "Google",
        device_model: "Pixel 6 Pro",
        screen_resolution: "3120x1440",
        total_ram: "12017676288",
        min_android: 12,
    },
    DeviceProfile {
        manufacturer: "Google",
        device_model: "Pixel 6a",
        screen_resolution: "2400x1080",
        total_ram: "5938152960",
        min_android: 12,
    },
    DeviceProfile {
        manufacturer: "Google",
        device_model: "Pixel 7",
        screen_resolution: "2400x1080",
        total_ram: "8026152960",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "Google",
        device_model: "Pixel 7 Pro",
        screen_resolution: "3120x1440",
        total_ram: "12017676288",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "Google",
        device_model: "Pixel 7a",
        screen_resolution: "2400x1080",
        total_ram: "8026152960",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "Google",
        device_model: "Pixel 8",
        screen_resolution: "2400x1080",
        total_ram: "8026152960",
        min_android: 14,
    },
    DeviceProfile {
        manufacturer: "Google",
        device_model: "Pixel 8 Pro",
        screen_resolution: "2992x1344",
        total_ram: "12017676288",
        min_android: 14,
    },
    DeviceProfile {
        manufacturer: "Google",
        device_model: "Pixel 8a",
        screen_resolution: "2400x1080",
        total_ram: "8026152960",
        min_android: 14,
    },
    DeviceProfile {
        manufacturer: "Google",
        device_model: "Pixel 9",
        screen_resolution: "2424x1080",
        total_ram: "12017676288",
        min_android: 14,
    },
    DeviceProfile {
        manufacturer: "Google",
        device_model: "Pixel 9 Pro",
        screen_resolution: "2856x1280",
        total_ram: "16065654784",
        min_android: 14,
    },
    DeviceProfile {
        manufacturer: "Google",
        device_model: "Pixel 9 Pro XL",
        screen_resolution: "2992x1344",
        total_ram: "16065654784",
        min_android: 14,
    },
    // Samsung
    DeviceProfile {
        manufacturer: "samsung",
        device_model: "SM-S901B",
        screen_resolution: "2340x1080",
        total_ram: "8026152960",
        min_android: 12,
    },
    DeviceProfile {
        manufacturer: "samsung",
        device_model: "SM-S906B",
        screen_resolution: "2340x1080",
        total_ram: "8026152960",
        min_android: 12,
    },
    DeviceProfile {
        manufacturer: "samsung",
        device_model: "SM-S908B",
        screen_resolution: "3088x1440",
        total_ram: "12017676288",
        min_android: 12,
    },
    DeviceProfile {
        manufacturer: "samsung",
        device_model: "SM-S911B",
        screen_resolution: "2340x1080",
        total_ram: "8026152960",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "samsung",
        device_model: "SM-S916B",
        screen_resolution: "2340x1080",
        total_ram: "8026152960",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "samsung",
        device_model: "SM-S918B",
        screen_resolution: "3088x1440",
        total_ram: "12017676288",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "samsung",
        device_model: "SM-S921B",
        screen_resolution: "2340x1080",
        total_ram: "8026152960",
        min_android: 14,
    },
    DeviceProfile {
        manufacturer: "samsung",
        device_model: "SM-S926B",
        screen_resolution: "2340x1080",
        total_ram: "12017676288",
        min_android: 14,
    },
    DeviceProfile {
        manufacturer: "samsung",
        device_model: "SM-S928B",
        screen_resolution: "3120x1440",
        total_ram: "12017676288",
        min_android: 14,
    },
    DeviceProfile {
        manufacturer: "samsung",
        device_model: "SM-A546B",
        screen_resolution: "2340x1080",
        total_ram: "8026152960",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "samsung",
        device_model: "SM-A346B",
        screen_resolution: "2340x1080",
        total_ram: "8026152960",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "samsung",
        device_model: "SM-A145F",
        screen_resolution: "2408x1080",
        total_ram: "3852152832",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "samsung",
        device_model: "SM-F731B",
        screen_resolution: "2640x1080",
        total_ram: "8026152960",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "samsung",
        device_model: "SM-F946B",
        screen_resolution: "2176x1812",
        total_ram: "12017676288",
        min_android: 13,
    },
    // Xiaomi / Redmi / POCO
    DeviceProfile {
        manufacturer: "Xiaomi",
        device_model: "2201123G",
        screen_resolution: "2400x1080",
        total_ram: "8026152960",
        min_android: 12,
    },
    DeviceProfile {
        manufacturer: "Xiaomi",
        device_model: "2211133G",
        screen_resolution: "2400x1080",
        total_ram: "8026152960",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "Xiaomi",
        device_model: "23078PND5G",
        screen_resolution: "2712x1220",
        total_ram: "8026152960",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "Xiaomi",
        device_model: "23127PN0CG",
        screen_resolution: "2670x1200",
        total_ram: "12017676288",
        min_android: 14,
    },
    DeviceProfile {
        manufacturer: "Xiaomi",
        device_model: "23021RAA2Y",
        screen_resolution: "2400x1080",
        total_ram: "3852152832",
        min_android: 12,
    },
    DeviceProfile {
        manufacturer: "Xiaomi",
        device_model: "23117RA68G",
        screen_resolution: "2712x1220",
        total_ram: "8026152960",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "Xiaomi",
        device_model: "23049PCD8G",
        screen_resolution: "2400x1080",
        total_ram: "8026152960",
        min_android: 13,
    },
    // OnePlus
    DeviceProfile {
        manufacturer: "OnePlus",
        device_model: "NE2213",
        screen_resolution: "3216x1440",
        total_ram: "8026152960",
        min_android: 12,
    },
    DeviceProfile {
        manufacturer: "OnePlus",
        device_model: "CPH2449",
        screen_resolution: "3216x1440",
        total_ram: "8026152960",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "OnePlus",
        device_model: "CPH2581",
        screen_resolution: "3168x1440",
        total_ram: "12017676288",
        min_android: 14,
    },
    DeviceProfile {
        manufacturer: "OnePlus",
        device_model: "CPH2491",
        screen_resolution: "2772x1240",
        total_ram: "8026152960",
        min_android: 13,
    },
    // Motorola
    DeviceProfile {
        manufacturer: "motorola",
        device_model: "motorola edge 40",
        screen_resolution: "2400x1080",
        total_ram: "8026152960",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "motorola",
        device_model: "motorola g84 5G",
        screen_resolution: "2400x1080",
        total_ram: "8026152960",
        min_android: 13,
    },
    // Sony
    DeviceProfile {
        manufacturer: "Sony",
        device_model: "XQ-DQ54",
        screen_resolution: "3840x1644",
        total_ram: "12017676288",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "Sony",
        device_model: "XQ-DE54",
        screen_resolution: "2520x1080",
        total_ram: "8026152960",
        min_android: 13,
    },
    // Nothing
    DeviceProfile {
        manufacturer: "Nothing",
        device_model: "A065",
        screen_resolution: "2412x1080",
        total_ram: "12017676288",
        min_android: 13,
    },
    DeviceProfile {
        manufacturer: "Nothing",
        device_model: "A142",
        screen_resolution: "2412x1084",
        total_ram: "8026152960",
        min_android: 14,
    },
    // Asus
    DeviceProfile {
        manufacturer: "asus",
        device_model: "ASUS_AI2205",
        screen_resolution: "2448x1080",
        total_ram: "12017676288",
        min_android: 13,
    },
];

pub(crate) const SAFE_TIMEZONES: &[&str] = &[
    // Europe
    "Europe/Dublin",
    "Europe/Zurich",
    "Europe/Prague",
    "Europe/Bratislava",
    "Europe/Budapest",
    "Europe/Bucharest",
    "Europe/Sofia",
    "Europe/Zagreb",
    "Europe/Vilnius",
    "Europe/Riga",
    "Europe/Tallinn",
    "Europe/Luxembourg",
    "Europe/Malta",
    // Americas
    "America/Mexico_City",
    "America/Argentina/Buenos_Aires",
    "America/Santiago",
    "America/Bogota",
    "America/Lima",
    "America/Montevideo",
    // Asia-Pacific
    "Asia/Tokyo",
    "Asia/Taipei",
    "Asia/Seoul",
    "Asia/Bangkok",
    "Asia/Manila",
    "Asia/Singapore",
];

/// A fake Android device identity used to fill in request headers.
///
/// [`DeviceInfo::generate`] (or [`Default`]) picks a real hardware profile and
/// builds a believable device from it. Save it next to the
/// [`Session`](crate::Session) and reuse it — keeping the same device across
/// runs is less likely to trip Cloudflare than making a new one every time.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DeviceInfo {
    /// Device type sent to the API (`2` = Android).
    pub device_type: u8,
    /// 16-hex-character device identifier.
    pub device_id: String,
    /// OS string, e.g. `"Android 14"`.
    pub os: String,
    /// Screen resolution as `"<height>x<width>"`.
    pub screen_resolution: String,
    /// Total RAM in bytes, as a string.
    pub total_ram: String,
    /// Advertising id (a random UUID).
    pub advertising_id: String,
    /// Marketing/model code, e.g. `"Pixel 8"` or `"SM-S921B"`.
    pub device_model: String,
    /// Device manufacturer, e.g. `"Google"` or `"samsung"`.
    pub manufacturer: String,
    /// IANA timezone name sent in the `L-Time-Zone` header.
    pub timezone: String,
    /// Locale string, e.g. `"en_US"`.
    pub locale: String,
    /// `Accept-Language` value, e.g. `"en-US"`.
    pub accept_language: String,
}

impl DeviceInfo {
    /// Builds a random device: a real hardware profile, an Android version that
    /// fits it, and a safe timezone.
    pub fn generate() -> Self {
        let profile = &DEVICE_PROFILES[rand::random_range(0..DEVICE_PROFILES.len())];
        let timezone = SAFE_TIMEZONES[rand::random_range(0..SAFE_TIMEZONES.len())];
        let device_id = format!("{:016x}", rand::random::<u64>());
        let android_version = rand::random_range(profile.min_android..=MAX_ANDROID_VERSION);

        Self {
            device_type: 2,
            device_id,
            os: format!("Android {android_version}"),
            screen_resolution: profile.screen_resolution.to_owned(),
            total_ram: profile.total_ram.to_owned(),
            advertising_id: uuid::Uuid::new_v4().to_string(),
            device_model: profile.device_model.to_owned(),
            manufacturer: profile.manufacturer.to_owned(),
            timezone: timezone.to_owned(),
            locale: "en_US".to_owned(),
            accept_language: "en-US".to_owned(),
        }
    }
}

impl Default for DeviceInfo {
    fn default() -> Self {
        Self::generate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_is_valid() {
        let d = DeviceInfo::generate();
        assert!(d.os.starts_with("Android "));
        assert_eq!(d.device_id.len(), 16);
        assert!(!d.device_model.is_empty());
    }
}
