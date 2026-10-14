use aggligator_fec::{Frame,recovery::{Feedback,SendWindow}};
use std::time::Duration;

#[test]
fn adaptive_retry_deadline_keeps_unacknowledged_data_and_suppresses_duplicate_copies() {
    let mut window=SendWindow::new(4,4096,Duration::from_millis(120),5).unwrap();
    let frame=Frame::Source{block:0,base:0,index:0,payload:vec![7;1300]};
    window.retain(&frame).unwrap();
    window.set_retry_cooldown(Duration::from_millis(350)).unwrap();
    let missing=Feedback{next:0,base:0,limit:1,missing:1};
    assert_eq!(window.feedback(missing,Duration::ZERO).unwrap().len(),1);
    assert!(window.feedback(missing,Duration::from_millis(120)).unwrap().is_empty());
    assert!(window.feedback(missing,Duration::from_millis(349)).unwrap().is_empty());
    assert_eq!(window.len(),1);
    assert_eq!(window.feedback(missing,Duration::from_millis(350)).unwrap().len(),1);
    assert!(window.set_retry_cooldown(Duration::ZERO).is_err());
    window.feedback(Feedback{next:1,base:1,limit:1,missing:0},Duration::from_millis(351)).unwrap();
    assert!(window.is_empty());
}
