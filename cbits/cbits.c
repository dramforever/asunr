#include <unistd.h>
#include <seccomp.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>

#define ss(c) SCMP_SYS(c)
const int safe_calls[] = {ss(brk), ss(arch_prctl), ss(mmap), ss(uname), ss(exit), ss(exit_group), ss(lseek)};
#undef ss

const int n_safe_calls = sizeof(safe_calls) / sizeof(int);

inline void die() {
  raise(SIGUSR1);
}

void guest_run(const char *program,
	       int input_fd,
	       int output_fd,
	       long time_limit,
	       long memory_limit) {

  if (input_fd >= 0 && -1 == dup2(input_fd, 0)) die();
  if (output_fd >= 0 && -1 == dup2(output_fd, 1)) die();
  
  if (-1 == fcntl(0, F_SETFL, 0)) die();
  if (-1 == fcntl(1, F_SETFL, 0)) die();


  if (memory_limit > 0) {
    struct rlimit rl;
    rl.rlim_cur = rl.rlim_max = memory_limit * 1024;
    if (-1 == setrlimit(RLIMIT_AS, &rl)) die();
  }

  if (time_limit > 0) {
    struct itimerval it;
    if (-1 == getitimer(ITIMER_REAL, &it)) die();

    it.it_value.tv_sec = time_limit / 1000;
    it.it_value.tv_usec = 1000 * (time_limit % 1000);

    if (-1 == setitimer(ITIMER_REAL, &it, 0)) die();
  }
  
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));

  if (ctx == 0) die();

  for (int i = 0; i < n_safe_calls; i ++)
    if (0 != seccomp_rule_add(ctx, SCMP_ACT_ALLOW, safe_calls[i], 0)) die();

  if (-1 == seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, 0))) die();
  if (-1 == seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, 1))) die();
  if (-1 == seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 1, SCMP_A0(SCMP_CMP_EQ, program))) die();
  if (-1 == seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, SCMP_A0(SCMP_CMP_EQ, 0))) die();
  if (-1 == seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, 1))) die();

  if (0 != seccomp_load(ctx)) die();

  seccomp_release(ctx);

  execl(program, program);

  die();
}

int run_sandboxed(const char *program,
		  int input_fd,
		  int output_fd,
		  long time_limit,
		  long memory_limit,
		  long *cputime,
		  long *maxrss) {
  pid_t pid = fork();

  if (pid < 0) return -1;
  else if (pid > 0) {
    /* Parent process */
    int status;
    struct rusage ru;
    if(-1 == wait4(pid, &status, 0, &ru)) return -1;
    *maxrss = ru.ru_maxrss;
    *cputime =
      (ru.ru_stime.tv_sec + ru.ru_utime.tv_sec) * 1000
      + (ru.ru_stime.tv_usec + ru.ru_utime.tv_usec) / 1000;
    return status;
  } else {
    guest_run(program, input_fd, output_fd, time_limit, memory_limit);
  }
}
