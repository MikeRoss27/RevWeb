#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Measure the exec'd scanner from a small native parent. Python's inherited
 * RSS high-water mark must not become the scanner's peak through fork/spawn. */
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    struct timespec start, end;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return 2;
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        if (!freopen("/dev/null", "w", stdout) || !freopen("/dev/null", "w", stderr)) _exit(126);
        execv(argv[1], &argv[1]);
        _exit(127);
    }
    int status;
    struct rusage usage;
    while (wait4(child, &status, 0, &usage) < 0) {
        if (errno != EINTR) return 2;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &end)) return 2;
    double elapsed = (double)(end.tv_sec - start.tv_sec) +
                     (double)(end.tv_nsec - start.tv_nsec) / 1000000000.0;
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    printf("{\"wall_seconds\":%.9f,\"max_rss_kib\":%ld,\"exit_code\":%d}\n", elapsed, usage.ru_maxrss, code);
    return 0;
}
