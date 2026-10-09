// Standalone synthetic samples only. No production input or raw payload export.
// Direct linked synchronous memcpy observation is not physical bus tracing.
// q8_fini uses ordinary process-local reset, never Force/hardware reset.
#include <acl/acl.h>
#include "q8_ops.h"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

static int M,K,N,uploads,downloads,integer_bad;
static bool observing=false;
static std::vector<int8_t> weights,limbs;
static uint64_t upload_hash;
static uint64_t fingerprint(const void *p,size_t n) {
    uint64_t h=14695981039346656037ULL;
    const auto *b=static_cast<const unsigned char *>(p);
    for(size_t i=0;i<n;++i) { h^=b[i]; h*=1099511628211ULL; }
    return h;
}
extern "C" aclError __real_aclrtMemcpy(void *,size_t,const void *,size_t,aclrtMemcpyKind);
extern "C" aclError __wrap_aclrtMemcpy(void *dst,size_t cap,const void *src,size_t count,aclrtMemcpyKind kind) {
    aclError rc=__real_aclrtMemcpy(dst,cap,src,count,kind);
    if(observing && rc==0 && kind==ACL_MEMCPY_HOST_TO_DEVICE) {
        ++uploads;
        if(count!=size_t(4*M*K)) ++integer_bad;
        else { const auto *p=static_cast<const int8_t *>(src); limbs.assign(p,p+count); upload_hash=fingerprint(src,count); }
    }
    if(observing && rc==0 && kind==ACL_MEMCPY_DEVICE_TO_HOST) {
        ++downloads;
        if(count!=size_t(4*M*N*sizeof(int32_t)) || limbs.size()!=size_t(4*M*K)) ++integer_bad;
        else {
            const auto *actual=static_cast<const int32_t *>(dst);
            for(int row=0;row<4*M;++row) for(int n=0;n<N;++n) {
                int64_t expected=0;
                for(int k=0;k<K;++k) expected+=int64_t(limbs[row*K+k])*weights[n*K+k];
                if(expected!=actual[row*N+n]) ++integer_bad;
            }
        }
    }
    return rc;
}

int main(int argc,char **argv) {
    if(argc!=2 || std::strcmp(argv[1],"--run-synthetic")) return 2;
    if(setenv("OTP_RNS_NO_VERIFY","1",1) || unsetenv("OTP_RNS_DEBUG")) return 2;
    std::puts("{\"event\":\"scope\",\"synthetic_only\":true,\"cpu_auto_correction\":false,\"physical_bus_capture\":false,\"fingerprint_claim\":\"sample_non_repetition_only_fnv1a64\"}");
    if(q8_init(0)) return 3;
    // Bounded covering set, not the full Cartesian product. 96 executions.
    const int shapes[][3]={{1,32,16},{2,128,32},{4,256,64},{4,32,64},{1,256,32},{2,128,16}};
    const char *patterns[]={"zero","positive_extreme","negative_extreme","sparse"};
    int failures=0,cases=0;
    for(const auto &shape:shapes) {
        M=shape[0]; K=shape[1]; N=shape[2];
        weights.resize(N*K);
        // Includes both int8 weight extremes; max dot <=256*127*128,
        // far below signed CRT interval. Scale keeps FP16 magnitude < 4096.
        for(int n=0;n<N;++n) for(int k=0;k<K;++k)
            weights[n*K+k]=int8_t(n%3==0?127:n%3==1?-128:((k*7+n*11)%255-127));
        void *dev_w=nullptr;
        if(aclrtMalloc(&dev_w,weights.size(),ACL_MEM_MALLOC_HUGE_FIRST) ||
           aclrtMemcpy(dev_w,weights.size(),weights.data(),weights.size(),ACL_MEMCPY_HOST_TO_DEVICE)) {
            ++failures; if(dev_w) aclrtFree(dev_w); break;
        }
        std::vector<float> scales(N,1.f/2048.f),input(M*K),out(M*N),reference(M*N);
        for(int pattern=0;pattern<4;++pattern) {
            for(int m=0;m<M;++m) for(int k=0;k<K;++k)
                input[m*K+k]=pattern==0?0.f:pattern==1?127.f:pattern==2?-127.f:
                    k==(m*17)%K?127.f:k==(m*17+1)%K?-127.f:0.f;
            // Inputs are exact integers, zero rows use scale=1 and other rows amax/127=1.
            for(int m=0;m<M;++m) for(int n=0;n<N;++n) {
                int64_t dot=0;
                for(int k=0;k<K;++k) dot+=int64_t(input[m*K+k])*weights[n*K+k];
                reference[m*N+n]=float(half(float(dot)*scales[n]));
            }
            for(int split=0;split<2;++split) {
                // Separate host allocations catch incorrect second-segment indexing.
                int n0=N/2;
                std::vector<int8_t> w0(weights.begin(),weights.begin()+n0*K),w1(weights.begin()+n0*K,weights.end());
                uint64_t previous=0;
                for(int repeat=0;repeat<2;++repeat) {
                    uploads=downloads=integer_bad=0; limbs.clear(); upload_hash=0;
                    std::fill(out.begin(),out.end(),NAN); observing=true;
                    int rc=split?q8_linear_otp_rns_raw_split(input.data(),M,K,dev_w,w0.data(),n0,w1.data(),scales.data(),N,out.data()):
                        q8_linear_otp_rns_raw(input.data(),M,K,dev_w,weights.data(),scales.data(),N,out.data());
                    observing=false;
                    int bad=0; for(size_t i=0;i<out.size();++i) if(out[i]!=reference[i]) ++bad;
                    bool fresh=repeat==0 || previous!=upload_hash;
                    bool pass=rc==0 && bad==0 && integer_bad==0 && uploads==1 && downloads==1 && fresh;
                    ++cases; if(!pass) ++failures;
                    std::printf("{\"event\":\"case\",\"M\":%d,\"K\":%d,\"N\":%d,\"pattern\":\"%s\",\"path\":\"%s\",\"repeat\":%d,\"rc\":%d,\"output_mismatches\":%d,\"raw_integer_limb_mismatches\":%d,\"H2D\":%d,\"D2H\":%d,\"h2d_fnv1a64\":\"%016llx\",\"repeat_fingerprint_differs\":%s,\"pass\":%s}\n",
                        M,K,N,patterns[pattern],split?"raw_split":"raw",repeat,rc,bad,integer_bad,uploads,downloads,(unsigned long long)upload_hash,fresh?"true":"false",pass?"true":"false");
                    previous=upload_hash;
                }
            }
        }
        if(aclrtMemset(dev_w,weights.size(),0,weights.size())) ++failures;
        if(aclrtFree(dev_w)) ++failures;
    }
    q8_fini();
    std::printf("{\"event\":\"summary\",\"cases\":%d,\"failed_cases_or_cleanup\":%d,\"pass\":%s}\n",cases,failures,cases==96 && failures==0?"true":"false");
    return cases==96 && failures==0?0:1;
}
