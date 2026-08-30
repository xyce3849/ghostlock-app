#define _GNU_SOURCE
#include "selinux_state.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

static int read_enforce_file(void) {
  int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return -1;

  char b[8] = {0};
  ssize_t n = read(fd, b, sizeof(b) - 1);
  int saved = errno;
  close(fd);
  errno = saved;
  if (n <= 0) {
    if (n == 0) errno = EIO;
    return -1;
  }
  if (b[0] == '0') return 0;
  if (b[0] == '1') return 1;
  errno = EINVAL;
  return -1;
}

int ghostlock_selinux_read_state(int *enforcing) {
  if (!enforcing) {
    errno = EINVAL;
    return -1;
  }
  int state = read_enforce_file();
  if (state < 0) return -1;
  *enforcing = state;
  return 0;
}

int ghostlock_selinux_restore_state(int enforcing) {
  if (enforcing != 0 && enforcing != 1) {
    errno = EINVAL;
    return -1;
  }

  int fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
  if (fd < 0) return -1;

  const char value = enforcing ? '1' : '0';
  ssize_t n = write(fd, &value, 1);
  int saved = errno;
  close(fd);
  errno = saved;
  if (n != 1) {
    if (n >= 0) errno = EIO;
    return -1;
  }
  return 0;
}

int ghostlock_selinux_verify_state(int expected_enforcing) {
  int actual = -1;
  if (ghostlock_selinux_read_state(&actual) < 0) return -1;
  if (actual != expected_enforcing) {
    errno = EIO;
    return -1;
  }
  return 0;
}
