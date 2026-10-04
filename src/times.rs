//! Epoch rendering for job schedules. PBS evaluates schedules in the server's
//! own zone — UTC for the container image — which is rarely the operator's, so
//! every run time is shown in both UTC and local time.

use plugin_toolkit::prelude::*;

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
pub struct When {
    pub epoch: i64,
    /// `YYYY-MM-DD HH:MM:SS +00:00`.
    pub utc: String,
    /// The same instant in local time (the orca host's zone, or `utc_offset`).
    pub local: String,
}

impl When {
    pub fn new(epoch: i64, offset: Option<i32>) -> Self {
        let local_offset = offset.unwrap_or_else(|| host_offset(epoch));
        Self {
            epoch,
            utc: format(epoch, 0),
            local: format(epoch, local_offset),
        }
    }
}

/// `+HH:MM` / `-HH:MM` / `Z` → seconds east of UTC.
pub fn parse_offset(s: &str) -> Result<i32> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("z") || s == "UTC" {
        return Ok(0);
    }
    let (sign, rest) = match s.as_bytes().first() {
        Some(b'+') => (1, &s[1..]),
        Some(b'-') => (-1, &s[1..]),
        _ => bail!("utc_offset '{s}' must look like +HH:MM or -HH:MM"),
    };
    let (h, m) = rest.split_once(':').unwrap_or((rest, "0"));
    let h: i32 = h
        .parse()
        .map_err(|_| anyhow!("utc_offset '{s}': bad hours"))?;
    let m: i32 = m
        .parse()
        .map_err(|_| anyhow!("utc_offset '{s}': bad minutes"))?;
    if h > 14 || m > 59 {
        bail!("utc_offset '{s}' is out of range");
    }
    Ok(sign * (h * 3600 + m * 60))
}

/// UTC offset of the host's zone at `epoch`, so DST is applied per instant.
fn host_offset(epoch: i64) -> i32 {
    let t = epoch as libc::time_t;
    // SAFETY: localtime_r writes only into the zeroed `tm` we own and returns
    // null on failure, which we treat as UTC.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return 0;
        }
        tm.tm_gmtoff as i32
    }
}

fn format(epoch: i64, offset: i32) -> String {
    let t = epoch + offset as i64;
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    let sign = if offset < 0 { '-' } else { '+' };
    let off = offset.abs();
    format!(
        "{y:04}-{mo:02}-{d:02} {:02}:{:02}:{:02} {sign}{:02}:{:02}",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60,
        off / 3600,
        off % 3600 / 60
    )
}

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian
/// (H. Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_and_offset_local() {
        // 2026-10-04 05:30:00 UTC, the willow→maple sync time.
        let w = When::new(1_791_091_800, Some(-6 * 3600));
        assert_eq!(w.utc, "2026-10-04 05:30:00 +00:00");
        assert_eq!(w.local, "2026-10-03 23:30:00 -06:00");
    }

    #[test]
    fn handles_epoch_and_leap_days() {
        assert_eq!(format(0, 0), "1970-01-01 00:00:00 +00:00");
        assert_eq!(format(951_782_400, 0), "2000-02-29 00:00:00 +00:00");
        assert_eq!(format(0, 5 * 3600 + 30 * 60), "1970-01-01 05:30:00 +05:30");
    }

    #[test]
    fn parses_offsets() {
        assert_eq!(parse_offset("-06:00").unwrap(), -21_600);
        assert_eq!(parse_offset("+05:30").unwrap(), 19_800);
        assert_eq!(parse_offset("Z").unwrap(), 0);
        assert!(parse_offset("6").is_err());
        assert!(parse_offset("+25:00").is_err());
    }

    #[test]
    fn host_offset_is_whole_minutes() {
        assert_eq!(host_offset(1_791_091_800) % 60, 0);
    }
}
