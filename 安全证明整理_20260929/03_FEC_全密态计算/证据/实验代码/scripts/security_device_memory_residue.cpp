/* Cross-process device memory residue probe (TDC-05 cleanup / FEC key reclamation).
 *
 * writer: allocate device memory, fill it with a unique marker, then either free it or exit
 *         without freeing so the driver reclaims it.
 * reader: allocate the same size in a NEW process and read it back WITHOUT initialising it.
 *         If the marker shows up, a later task can observe a previous task's device data.
 *
 * The reader also performs a self-check (write its own marker, read it back) so that a
 * "no hits" result cannot be explained by a broken read path. Synthetic data only.
 */
#include <acl/acl.h>
#include <unistd.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static size_t count_occurrences(const std::vector<char> &buf, const std::string &needle) {
    if (needle.empty() || buf.size() < needle.size()) return 0;
    size_t hits = 0;
    const char *base = buf.data();
    const char *end = base + buf.size();
    const char *p = base;
    while (true) {
        const void *found = memmem(p, static_cast<size_t>(end - p), needle.data(), needle.size());
        if (!found) break;
        ++hits;
        p = static_cast<const char *>(found) + 1;
        if (p >= end) break;
    }
    return hits;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <write|write-nofree|read> <marker> <megabytes>\n", argv[0]);
        return 2;
    }
    const std::string mode = argv[1];
    const std::string marker = argv[2];
    const size_t bytes = static_cast<size_t>(atoi(argv[3])) * 1024u * 1024u;
    if (bytes == 0) return 2;

    if (aclInit(nullptr) != ACL_SUCCESS) { printf("{\"error\":\"aclInit\"}\n"); return 3; }
    if (aclrtSetDevice(0) != ACL_SUCCESS) { printf("{\"error\":\"setDevice\"}\n"); return 3; }
    aclrtContext ctx = nullptr;
    if (aclrtCreateContext(&ctx, 0) != ACL_SUCCESS) { printf("{\"error\":\"createContext\"}\n"); return 3; }

    void *dev = nullptr;
    if (aclrtMalloc(&dev, bytes, ACL_MEM_MALLOC_HUGE_FIRST) != ACL_SUCCESS) {
        printf("{\"error\":\"aclrtMalloc\",\"bytes\":%zu}\n", bytes);
        return 4;
    }

    if (mode == "write" || mode == "write-nofree") {
        std::vector<char> host(bytes);
        for (size_t off = 0; off < bytes; off += marker.size())
            memcpy(host.data() + off, marker.data(),
                   std::min(marker.size(), bytes - off));
        if (aclrtMemcpy(dev, bytes, host.data(), bytes, ACL_MEMCPY_HOST_TO_DEVICE) != ACL_SUCCESS) {
            printf("{\"error\":\"h2d\"}\n");
            return 5;
        }
        bool freed = false;
        if (mode == "write") { freed = aclrtFree(dev) == ACL_SUCCESS; dev = nullptr; }
        printf("{\"role\":\"%s\",\"bytes\":%zu,\"freed\":%s}\n",
               mode.c_str(), bytes, freed ? "true" : "false");
        fflush(stdout);
        if (mode == "write-nofree") _exit(0);  /* leave reclamation to the driver */
    } else {
        /* read back untouched freshly allocated device memory */
        std::vector<char> host(bytes, 0);
        if (aclrtMemcpy(host.data(), bytes, dev, bytes, ACL_MEMCPY_DEVICE_TO_HOST) != ACL_SUCCESS) {
            printf("{\"error\":\"d2h\"}\n");
            return 5;
        }
        size_t hits = count_occurrences(host, marker);
        size_t nonzero = 0;
        for (size_t i = 0; i < bytes; ++i) if (host[i]) ++nonzero;

        /* self-check: the read path must be able to see something we just wrote */
        const std::string self = "SELFCHECK" + marker.substr(0, 8);
        std::vector<char> probe(bytes);
        for (size_t off = 0; off < bytes; off += self.size())
            memcpy(probe.data() + off, self.data(), std::min(self.size(), bytes - off));
        size_t self_hits = 0;
        if (aclrtMemcpy(dev, bytes, probe.data(), bytes, ACL_MEMCPY_HOST_TO_DEVICE) == ACL_SUCCESS) {
            std::vector<char> back(bytes, 0);
            if (aclrtMemcpy(back.data(), bytes, dev, bytes, ACL_MEMCPY_DEVICE_TO_HOST) == ACL_SUCCESS)
                self_hits = count_occurrences(back, self);
        }
        printf("{\"role\":\"read\",\"bytes\":%zu,\"marker_hits\":%zu,\"nonzero_bytes\":%zu,"
               "\"self_check_hits\":%zu}\n", bytes, hits, nonzero, self_hits);
        aclrtFree(dev);
        dev = nullptr;
    }

    if (dev) aclrtFree(dev);
    aclrtDestroyContext(ctx);
    aclrtResetDevice(0);
    aclFinalize();
    return 0;
}
