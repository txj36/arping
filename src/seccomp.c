#define _GNU_SOURCE
#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "arping.h"
#include "cast.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


#if !USE_SECCOMP
#error foo
#else
#include <seccomp.h>

static void seccomp_allow(scmp_filter_ctx ctx, const char* name)
{
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_syscall_resolve_name(name), 0)) {
                if (verbose) {
                        fprintf(stderr, "arping: seccomp_rule_add_exact(%s): %s",
                                name, strerror(errno));
                }
        }
}

void drop_seccomp(int libnet_fd)
{
        //scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(13));
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
        if (!ctx) {
                perror("seccomp_init()");
                exit(1);
        }

        //
        // Whitelist.
        //

        // Write to stdout and stderr.
#if HAVE_SECCOMP_SYSCALL_statx
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statx), 1, SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO))) {
                perror("seccomp_rule_add(statx stdout)");
                exit(1);
        }
#endif
#if HAVE_SECCOMP_SYSCALL_fstat
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO))) {
                perror("seccomp_rule_add(fstat stdout)");
                exit(1);
        }
#endif
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, STDOUT_FILENO))) {
                perror("seccomp_rule_add(write stdout)");
                exit(1);
        }
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_EQ, STDERR_FILENO))) {
                perror("seccomp_rule_add(write stderr)");
                exit(1);
        }

        // Libnet.
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1, SCMP_A0(SCMP_CMP_EQ, cast_int_uint(libnet_fd, NULL)))) {
                perror("seccomp_rule_add(ioctl libnet)");
                exit(1);
        }
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 1, SCMP_A0(SCMP_CMP_EQ, cast_int_uint(libnet_fd, NULL)))) {
                perror("seccomp_rule_add(sendto libnet)");
                exit(1);
        }

        // Other.
        seccomp_allow(ctx, "select");
        seccomp_allow(ctx, "pselect6");
        seccomp_allow(ctx, "newfstatat");
        seccomp_allow(ctx, "exit_group");
        seccomp_allow(ctx, "rt_sigreturn");
#if HAVE_SECCOMP_SYSCALL_clock_gettime64
        seccomp_allow(ctx, "clock_gettime64");
#endif

        // Load.
        if (seccomp_load(ctx)) {
                perror("seccomp_load()");
                exit(1);
        }
        seccomp_release(ctx);
        if (verbose > 1) {
                printf("arping: Successfully applied seccomp policy\n");
        }
}
#endif
