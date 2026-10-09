/* LD_PRELOAD shim for FEC-08 case 6: make getrandom() fail on demand.
 *
 * Only fails while the trigger file exists, so process start-up, model load and
 * the ACL runtime still get real entropy; the fault is confined to the one call
 * under test. Used exclusively by security_fault_injection.c.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>

#define ARM_FILE "/tmp/otp_fault_arm"

typedef ssize_t (*getrandom_fn)(void *, size_t, unsigned int);

ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
    static getrandom_fn real = NULL;
    if (!real) real = (getrandom_fn)dlsym(RTLD_NEXT, "getrandom");
    if (access(ARM_FILE, F_OK) == 0) {
        errno = EIO;
        return -1;
    }
    if (!real) { errno = ENOSYS; return -1; }
    return real(buf, buflen, flags);
}
