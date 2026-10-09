// Synthetic-only, standalone aarch64/CANN probe. Never preload into a service.
// Compile frozen q8_ops.c and st35.c as C++ with the frozen Makefile flags/libs,
// add -I<frozen-dir> and -Wl,--wrap=aclrtMemcpy. Capture stdout AND stderr.
// q8_fini performs normal process-local aclrtResetDevice (no Force/hardware reset).
// This observes direct linked synchronous copies, NOT physical PCIe traffic or
// copies internal to shared libraries. Hashes are FNV-1a64 fingerprints, not SHA.
#include <acl/acl.h>
#include "q8_ops.h"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

static constexpr int K=32, N=16;
static int batch=0, repetition=0, copies=0, h2d=0, d2h=0, limb_bad=0;
static int8_t weights[N*K];
static std::vector<float> inputs;
static std::vector<int8_t> quantized, uploaded_limbs;

static uint64_t fingerprint(const void *p, size_t n) {
    const unsigned char *b=static_cast<const unsigned char *>(p);
    uint64_t h=14695981039346656037ULL;
    for(size_t i=0;i<n;++i) { h^=b[i]; h*=1099511628211ULL; }
    return h;
}
static bool contains(const void *p,size_t n,const void *needle,size_t len) {
    if(!len || len>n) return false;
    const auto *b=static_cast<const unsigned char *>(p);
    for(size_t i=0;i+len<=n;++i) if(!std::memcmp(b+i,needle,len)) return true;
    return false;
}
extern "C" aclError __real_aclrtMemcpy(void *,size_t,const void *,size_t,aclrtMemcpyKind);
extern "C" aclError __wrap_aclrtMemcpy(void *dst,size_t cap,const void *src,
                                      size_t count,aclrtMemcpyKind kind) {
    const bool up=kind==ACL_MEMCPY_HOST_TO_DEVICE;
    const bool down=kind==ACL_MEMCPY_DEVICE_TO_HOST;
    // All host buffers belong to this synthetic standalone process.
    const aclError rc=__real_aclrtMemcpy(dst,cap,src,count,kind);
    if((up||down) && rc==0) {
        const void *host=up?src:dst;
        bool row_match=false;
        for(int m=0;m<batch;++m)
            row_match |= contains(host,count,quantized.data()+m*K,K);
        std::printf("{\"event\":\"copy\",\"M\":%d,\"repeat\":%d,\"direction\":\"%s\",\"bytes\":%zu,\"fnv1a64\":\"%016llx\",\"contains_float_input\":%s,\"contains_quantized_row\":%s}\n",
            batch,repetition,up?"H2D":"D2H",count,
            (unsigned long long)fingerprint(host,count),
            contains(host,count,inputs.data(),inputs.size()*sizeof(float))?"true":"false",
            row_match?"true":"false");
        ++copies;
        if(batch && up && count==size_t(4*batch*K)) {
            ++h2d;
            const auto *p=static_cast<const int8_t *>(src);
            uploaded_limbs.assign(p,p+count);
        }
        if(batch && down && count==size_t(4*batch*N*sizeof(int32_t))) {
            ++d2h;
            if(uploaded_limbs.size()!=size_t(4*batch*K)) ++limb_bad;
            else {
                const auto *y=static_cast<const int32_t *>(dst);
                for(int r=0;r<4*batch;++r) for(int n=0;n<N;++n) {
                    int32_t ref=0;
                    for(int k=0;k<K;++k) ref+=int32_t(uploaded_limbs[r*K+k])*weights[n*K+k];
                    if(ref!=y[r*N+n]) ++limb_bad;
                }
            }
        }
    }
    return rc;
}

int main(int argc,char **argv) {
    if(argc!=2 || std::strcmp(argv[1],"--run-synthetic")) {
        std::fprintf(stderr,"Explicit --run-synthetic required; device 0 only; no production input.\n");
        return 2;
    }
    // Presence disables automatic CPU correction; setting value 0 would ALSO disable it.
    if(setenv("OTP_RNS_NO_VERIFY","1",1) || unsetenv("OTP_RNS_DEBUG")) return 2;
    std::printf("{\"event\":\"scope\",\"synthetic_only\":true,\"cpu_auto_correction\":false,\"physical_bus_capture\":false}\n");
    if(q8_init(0)) return 3;
    void *dev_w=nullptr;
    int failures=0;
    for(int n=0;n<N;++n) for(int k=0;k<K;++k) weights[n*K+k]=int8_t((n*11+k*7)%31-15);
    if(aclrtMalloc(&dev_w,sizeof(weights),ACL_MEM_MALLOC_HUGE_FIRST) ||
       aclrtMemcpy(dev_w,sizeof(weights),weights,sizeof(weights),ACL_MEMCPY_HOST_TO_DEVICE)) {
        if(dev_w) aclrtFree(dev_w);
        q8_fini(); return 4;
    }
    float scales[N]; for(int n=0;n<N;++n) scales[n]=float(n+1)/128.f;
    for(batch=1;batch<=2;++batch) {
        inputs.resize(batch*K); quantized.resize(batch*K);
        std::vector<float> xs(batch), out(batch*N), reference(batch*N);
        for(int m=0;m<batch;++m) {
            // amax=127 => exact scale 1; quantization cannot obscure integer errors.
            for(int k=0;k<K;++k) inputs[m*K+k]=float((k*13+m*17)%127-63);
            inputs[m*K]=127.f;
            float amax=0; for(int k=0;k<K;++k) amax=std::max(amax,std::fabs(inputs[m*K+k]));
            xs[m]=amax>0?amax/127.f:1.f;
            for(int k=0;k<K;++k) quantized[m*K+k]=int8_t(std::max(-127,std::min(127,int(std::lrint(inputs[m*K+k]/xs[m])))));
            for(int n=0;n<N;++n) {
                int32_t dot=0; for(int k=0;k<K;++k) dot+=int32_t(quantized[m*K+k])*weights[n*K+k];
                reference[m*N+n]=float(half(float(dot)*xs[m]*scales[n]));
            }
        }
        for(repetition=0;repetition<2;++repetition) {
            h2d=d2h=limb_bad=0; uploaded_limbs.clear();
            std::fill(out.begin(),out.end(),NAN);
            int rc=q8_linear_otp_rns_raw(inputs.data(),batch,K,dev_w,weights,scales,N,out.data());
            int bad=0; for(size_t i=0;i<out.size();++i) if(out[i]!=reference[i]) ++bad;
            bool pass=rc==0 && bad==0 && limb_bad==0 && h2d==1 && d2h==1;
            if(!pass) ++failures;
            std::printf("{\"event\":\"case\",\"M\":%d,\"K\":32,\"N\":16,\"repeat\":%d,\"rc\":%d,\"output_mismatches\":%d,\"raw_integer_limb_mismatches\":%d,\"H2D\":%d,\"D2H\":%d,\"pass\":%s}\n",batch,repetition,rc,bad,limb_bad,h2d,d2h,pass?"true":"false");
        }
    }
    batch=0;
    if(aclrtMemset(dev_w,sizeof(weights),0,sizeof(weights))) ++failures;
    if(aclrtFree(dev_w)) ++failures;
    q8_fini();
    std::printf("{\"event\":\"summary\",\"failed_cases_or_cleanup\":%d,\"observed_copies\":%d}\n",failures,copies);
    return failures?1:0;
}
