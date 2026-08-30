#ifndef GHOSTLOCK_SELINUX_STATE_H
#define GHOSTLOCK_SELINUX_STATE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Snapshot and restore the SELinux enforcement state without changing the
 * existing GhostLock execution path. These helpers are intentionally kept
 * independent from the exploit code so they can be reused by cleanup paths.
 *
 * Return values: 0 on success, -1 on failure (errno is preserved/set).
 */
int ghostlock_selinux_read_state(int *enforcing);
int ghostlock_selinux_restore_state(int enforcing);
int ghostlock_selinux_verify_state(int expected_enforcing);

#ifdef __cplusplus
}
#endif

#endif
