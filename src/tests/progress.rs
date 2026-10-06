use super::*;

#[test]
fn fraction_is_zero_before_any_phase() {
    assert_eq!(Progress::new().fraction(), 0.0);
}

#[test]
fn phases_weigh_equally() {
    let progress = Progress::new();
    progress.start_phase(0, 2, 10);
    progress.advance(5);
    assert_eq!(progress.fraction(), 0.25);
    progress.start_phase(1, 2, 4);
    progress.advance(2);
    assert_eq!(progress.fraction(), 0.75);
    progress.advance(2);
    assert_eq!(progress.fraction(), 1.0);
}

#[test]
fn overshoot_and_empty_phases_stay_within_bounds() {
    let progress = Progress::new();
    progress.start_phase(0, 1, 3);
    progress.advance(7);
    assert_eq!(progress.fraction(), 1.0);
    progress.start_phase(0, 2, 0);
    assert_eq!(progress.fraction(), 0.5);
}
