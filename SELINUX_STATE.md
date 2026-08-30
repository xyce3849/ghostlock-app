# SELinux state helper

This tree now contains a small, independent SELinux state helper in
`src/core/selinux_state.[ch]`.

It provides three operations:

- `ghostlock_selinux_read_state()` — reads `/sys/fs/selinux/enforce` and returns
  the current state (`1` enforcing, `0` permissive).
- `ghostlock_selinux_restore_state()` — restores a previously saved state.
- `ghostlock_selinux_verify_state()` — verifies that the expected state is
  currently active.

The helper does **not** change GhostLock's existing exploit/control flow. It is
intended for legitimate cleanup and lifecycle handling where an application
needs to restore the SELinux state it observed before an operation.

The build includes the helper so it is compiled together with the native core.
Permissions on `/sys/fs/selinux/enforce` remain subject to Android SELinux and
kernel policy; a failed write is reported to the caller rather than treated as
success.
