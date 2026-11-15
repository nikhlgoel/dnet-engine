// SPDX-License-Identifier: GPL-3.0-or-later
//! The tray icon's pictures: the tunnel mark with its doorway showing the state (design-system §5, the lamps).
//!
//! The pictures are drawn once, from `docs/design/icon/`, and carried in the program as PNG so the tray needs no
//! drawing code and no file at run time. Each state is a different *shape* (see [`dnet_view::tray::Lamp`]), so the
//! state reads in greyscale and at 16 pixels.
//!
//! **Only one state moves.** While the service is finding a way through, the doorway fills and drains, a breath of
//! about a second and a half (the same period as the window's probe scan, `--probe-period`). Nothing else animates,
//! because nothing else is being tried: a tray icon that moved while connected, or while failed, would say something
//! was happening that is not (design-system principle 11).

use std::time::Duration;

use dnet_view::tray::Lamp;

/// How many pictures the probing breath has.
pub const PROBE_FRAMES: usize = 12;

/// How long each picture of the breath stays: 12 of them make about 1.6 seconds.
pub const PROBE_STEP: Duration = Duration::from_millis(133);

macro_rules! png {
    ($name:literal) => {
        include_bytes!(concat!("../icons/tray/", $name, ".png")).as_slice()
    };
}

const PROBE: [&[u8]; PROBE_FRAMES] = [
    png!("probe-00"),
    png!("probe-01"),
    png!("probe-02"),
    png!("probe-03"),
    png!("probe-04"),
    png!("probe-05"),
    png!("probe-06"),
    png!("probe-07"),
    png!("probe-08"),
    png!("probe-09"),
    png!("probe-10"),
    png!("probe-11"),
];

/// The picture for `lamp`; for [`Lamp::Probe`], the one at `step` of the breath (wrapped round).
pub fn frame(lamp: Lamp, step: usize) -> &'static [u8] {
    match lamp {
        Lamp::Off => png!("off"),
        Lamp::Probe => PROBE[step % PROBE_FRAMES],
        Lamp::Ok => png!("ok"),
        Lamp::Warn => png!("warn"),
        Lamp::Fail => png!("fail"),
        Lamp::Down => png!("down"),
    }
}

/// The picture as an icon the tray can show, or `None` if it cannot be read (the tray then keeps what it had).
pub fn image(lamp: Lamp, step: usize) -> Option<tauri::image::Image<'static>> {
    tauri::image::Image::from_bytes(frame(lamp, step)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Lamp; 6] = [
        Lamp::Off,
        Lamp::Probe,
        Lamp::Ok,
        Lamp::Warn,
        Lamp::Fail,
        Lamp::Down,
    ];

    /// The width and height written in a PNG's first chunk.
    fn size(png: &[u8]) -> (u32, u32) {
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n", "not a PNG");
        let word = |at: usize| u32::from_be_bytes(png[at..at + 4].try_into().unwrap());
        (word(16), word(20))
    }

    #[test]
    fn every_state_has_a_real_picture_of_the_same_size() {
        for lamp in ALL {
            assert_eq!(size(frame(lamp, 0)), (64, 64), "{lamp:?}");
        }
        for step in 0..PROBE_FRAMES {
            assert_eq!(size(frame(Lamp::Probe, step)), (64, 64), "step {step}");
        }
    }

    #[test]
    fn the_states_are_different_pictures() {
        let pictures: Vec<&[u8]> = ALL.iter().map(|lamp| frame(*lamp, 3)).collect();
        for (i, a) in pictures.iter().enumerate() {
            for b in &pictures[i + 1..] {
                assert_ne!(a, b, "two states share a picture");
            }
        }
    }

    #[test]
    fn the_breath_moves_and_comes_round() {
        assert_ne!(frame(Lamp::Probe, 0), frame(Lamp::Probe, 4));
        assert_eq!(frame(Lamp::Probe, 0), frame(Lamp::Probe, PROBE_FRAMES));
    }

    #[test]
    fn only_the_probing_state_has_more_than_one_picture() {
        for lamp in [Lamp::Off, Lamp::Ok, Lamp::Warn, Lamp::Fail, Lamp::Down] {
            assert_eq!(frame(lamp, 0), frame(lamp, 7), "{lamp:?} must not move");
        }
    }

    #[test]
    fn the_breath_is_about_the_windows_probe_period() {
        let total = PROBE_STEP * u32::try_from(PROBE_FRAMES).unwrap();
        assert!((1500..=1700).contains(&total.as_millis()), "{total:?}");
    }
}
