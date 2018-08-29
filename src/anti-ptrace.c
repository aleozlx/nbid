#include <sys/ptrace.h>
int anti_ptrace() {
    int _ = 0;
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == 0) _ = 2;
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) _ *= 3;
    if (_ == 6) return 0;
    else return -1;
}
