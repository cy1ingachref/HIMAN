use super::*;
use himan_proto::DeviceId;

fn ids(task: &str, owner: &str) -> (String, DeviceId) {
    (task.to_owned(), DeviceId::new(owner))
}

#[test]
fn registered_task_is_owned_at_epoch_zero() {
    let (task, owner) = ids("t1", "pc-1");
    let mut reg = OwnerRegistry::new();
    reg.register(task.clone(), owner.clone()).unwrap();
    let o = reg.get(&task).unwrap();
    assert_eq!(o.owner, owner);
    assert_eq!(o.epoch, 0);
}

#[test]
fn owner_can_write_at_the_current_epoch() {
    let (task, owner) = ids("t1", "pc-1");
    let mut reg = OwnerRegistry::new();
    reg.register(task.clone(), owner.clone()).unwrap();
    assert!(reg.check_write(&task, &owner, 0).is_ok());
}

#[test]
fn non_owner_is_rejected() {
    let (task, owner) = ids("t1", "pc-1");
    let other = DeviceId::new("phone-1");
    let mut reg = OwnerRegistry::new();
    reg.register(task.clone(), owner).unwrap();
    let err = reg.check_write(&task, &other, 0).unwrap_err();
    assert!(matches!(err, FenceError::NotOwner { .. }));
}

#[test]
fn stale_epoch_is_rejected() {
    let (task, owner) = ids("t1", "pc-1");
    let mut reg = OwnerRegistry::new();
    reg.register(task.clone(), owner.clone()).unwrap();
    // Orchestrator committed to epoch 1; the old owner still sends epoch 0.
    reg.commit(&task, DeviceId::new("phone-1"), 1).unwrap();
    let err = reg.check_write(&task, &owner, 0).unwrap_err();
    match err {
        FenceError::StaleEpoch {
            epoch,
            current_epoch,
            ..
        } => {
            assert_eq!(epoch, 0);
            assert_eq!(current_epoch, 1);
        }
        other => panic!("expected StaleEpoch, got {other:?}"),
    }
}

#[test]
fn a_stale_write_from_the_old_owner_is_reported_as_stale() {
    // After the commit the old device is behind on the epoch *and* no longer
    // the owner. Epoch is checked first, so the audit line says "stale epoch"
    // -- the detail that distinguishes a partitioned old owner from a random
    // device that never owned the task.
    let (task, owner) = ids("t1", "pc-1");
    let mut reg = OwnerRegistry::new();
    reg.register(task.clone(), owner.clone()).unwrap();
    reg.commit(&task, DeviceId::new("phone-1"), 1).unwrap();
    let err = reg.check_write(&task, &owner, 0).unwrap_err();
    assert!(matches!(err, FenceError::StaleEpoch { .. }));
}

#[test]
fn a_device_at_the_current_epoch_that_is_not_the_owner_is_refused() {
    // A third device that guesses the current epoch still cannot write.
    let (task, owner) = ids("t1", "pc-1");
    let mut reg = OwnerRegistry::new();
    reg.register(task.clone(), owner).unwrap();
    let err = reg
        .check_write(&task, &DeviceId::new("phone-1"), 0)
        .unwrap_err();
    assert!(matches!(err, FenceError::NotOwner { .. }));
}

#[test]
fn commit_moves_ownership_and_bumps_the_epoch() {
    let (task, owner) = ids("t1", "pc-1");
    let target = DeviceId::new("phone-1");
    let mut reg = OwnerRegistry::new();
    reg.register(task.clone(), owner).unwrap();
    let updated = reg.commit(&task, target.clone(), 1).unwrap();
    assert_eq!(updated.owner, target);
    assert_eq!(updated.epoch, 1);
    assert!(reg.check_write(&task, &target, 1).is_ok());
}

#[test]
fn commit_refuses_an_epoch_jump() {
    let (task, owner) = ids("t1", "pc-1");
    let target = DeviceId::new("phone-1");
    let mut reg = OwnerRegistry::new();
    reg.register(task.clone(), owner).unwrap();
    // Jumping to epoch 5 would leave the door open to a forged epoch 2-4.
    let err = reg.commit(&task, target, 5).unwrap_err();
    assert!(matches!(err, FenceError::StaleEpoch { .. }));
}

#[test]
fn commit_refuses_a_replayed_epoch() {
    let (task, owner) = ids("t1", "pc-1");
    let mut reg = OwnerRegistry::new();
    reg.register(task.clone(), owner.clone()).unwrap();
    reg.commit(&task, DeviceId::new("phone-1"), 1).unwrap();
    // Replaying the same commit must not move ownership back.
    let err = reg.commit(&task, owner, 1).unwrap_err();
    assert!(matches!(err, FenceError::StaleEpoch { .. }));
}

#[test]
fn unknown_task_is_refused_for_both_write_and_commit() {
    let mut reg = OwnerRegistry::new();
    let device = DeviceId::new("pc-1");
    let err = reg.check_write("ghost", &device, 0).unwrap_err();
    assert!(matches!(err, FenceError::NotOwner { .. }));
    let err = reg.commit("ghost", device, 1).unwrap_err();
    assert!(matches!(err, FenceError::NotOwner { .. }));
}

#[test]
fn registering_an_existing_task_with_a_different_owner_is_refused() {
    let (task, owner) = ids("t1", "pc-1");
    let mut reg = OwnerRegistry::new();
    reg.register(task.clone(), owner).unwrap();
    let err = reg.register(task, DeviceId::new("phone-1")).unwrap_err();
    assert!(matches!(err, FenceError::NotOwner { .. }));
}

#[test]
fn re_registering_the_same_owner_is_idempotent() {
    let (task, owner) = ids("t1", "pc-1");
    let mut reg = OwnerRegistry::new();
    reg.register(task.clone(), owner.clone()).unwrap();
    assert!(reg.register(task, owner).is_ok());
    assert_eq!(reg.len(), 1);
}

#[test]
fn epochs_can_advance_repeatedly() {
    let (task, owner) = ids("t1", "pc-1");
    let mut reg = OwnerRegistry::new();
    reg.register(task.clone(), owner).unwrap();
    reg.commit(&task, DeviceId::new("phone-1"), 1).unwrap();
    reg.commit(&task, DeviceId::new("pc-1"), 2).unwrap();
    assert_eq!(reg.get(&task).unwrap().epoch, 2);
    assert!(reg.check_write(&task, &DeviceId::new("pc-1"), 2).is_ok());
}

#[test]
fn error_text_names_the_task_and_devices() {
    let (task, owner) = ids("t1", "pc-1");
    let mut reg = OwnerRegistry::new();
    reg.register(task.clone(), owner).unwrap();
    let err = reg
        .check_write(&task, &DeviceId::new("phone-1"), 0)
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains("t1"));
    assert!(text.contains("phone-1"));
    assert!(text.contains("pc-1"));
}
