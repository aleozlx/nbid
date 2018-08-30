// Flaw: can't exec without receiving SIGTRAP after calling this
#if 0
#include <sys/ptrace.h>
int anti_ptrace() {
    int _ = 0;
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == 0) _ = 2;
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) _ *= 3;
    if (_ == 6) return 0;
    else return -1;
}
#endif

// Flaw: needs CAP_SYS_PTRACE capability with restricted ptrace.
//    tldr: can't attach existing parent unless someone do "sudo setcap cap_sys_ptrace+ep"
// ref: https://stackoverflow.com/questions/3596781/how-to-detect-if-the-current-process-is-being-run-by-gdb/24419586
#if 0
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
int anti_ptrace() {
    pid_t my_pid = getpid();
    pid_t tracer = fork();
    if (tracer == -1) return -1;
    if (tracer == 0) {
        int ret = 0;
        if (ptrace(PTRACE_ATTACH, my_pid, NULL, NULL) == 0) {
          waitpid(my_pid, NULL, 0);
          ptrace(PTRACE_DETACH, my_pid, NULL, NULL);
          _exit(0);
        }
      else _exit(1);
    } else {
        int status;
        wait(&status);
        return status == 0 ? 0 : -1;
    }
}
#endif

// Best bet? /proc/self/status: TracerPid
// ref: https://unix.stackexchange.com/questions/413697/how-do-i-hide-tracerpid-from-a-process
#if 1
#include <stdio.h>
int anti_ptrace() {
    FILE *f = fopen("/proc/self/status", "r");
    int pid = 0;
    char *s = NULL;
    size_t n = 0;
    if (f != NULL) {             
        while (getline(&s, &n, f) >= 0) {
            char *temp;
            temp = strstr(s, "TracerPid:");
            if (temp != NULL) {
                pid = strtol(temp + 0xb, NULL, 10);
                break;
            }
        }
        if (s != NULL) { free(s); }
        fclose(f);
    }
    return pid == 0 ? 0 : -1;
}
#endif
