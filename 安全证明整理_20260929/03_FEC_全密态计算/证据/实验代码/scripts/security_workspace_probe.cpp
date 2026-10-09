// Standalone synthetic observation only: same-TU access is not an attacker primitive.
// No production memory, no device fault injection, no reads after free.
#include "q8_ops.c"
#include <vector>
#include <algorithm>

struct Tracked { const char *name; void *ptr; size_t bytes; };
static Tracked tracked[10];
static int tracked_count, freed_count, nonzero_frees, fail_rng, injected;
static size_t nonzero(const void *p, size_t n) {
    const unsigned char *b=(const unsigned char *)p; size_t z=0;
    for(size_t i=0;i<n;++i) z+=b[i]!=0;
    return z;
}
static unsigned long long fp(const void *p,size_t n) {
    const unsigned char *b=(const unsigned char *)p;
    unsigned long long h=14695981039346656037ULL;
    for(size_t i=0;i<n;++i) {h^=b[i];h*=1099511628211ULL;}
    return h;
}
extern "C" void __real_free(void *);
extern "C" void __wrap_free(void *p) {
    for(int i=0;i<tracked_count;++i) if(p && p==tracked[i].ptr) {
        size_t n=nonzero(p,tracked[i].bytes); // Valid allocated memory, BEFORE real free.
        printf("{\"event\":\"pre_free\",\"buffer\":\"%s\",\"bytes\":%zu,\"nonzero_bytes\":%zu}\n",tracked[i].name,tracked[i].bytes,n);
        ++freed_count; nonzero_frees+=n!=0; tracked[i].ptr=nullptr;
    }
    __real_free(p);
}
extern "C" ssize_t __real_getrandom(void *,size_t,unsigned int);
extern "C" ssize_t __wrap_getrandom(void *p,size_t n,unsigned int f) {
    if(fail_rng) {++injected;errno=EIO;return -1;}
    return __real_getrandom(p,n,f);
}
static void observe(const char *phase,int M,const std::vector<int8_t>& expected) {
    RnsWorkspace &w=g_rns_ws[0];
    printf("{\"event\":\"workspace\",\"phase\":\"%s\",\"M\":%d,\"mcap\":%zu,\"xq_matches_synthetic\":%s,\"xq_nonzero\":%zu,\"r0_nonzero\":%zu,\"r1_nonzero\":%zu,\"limbs_nonzero\":%zu,\"mask_limbs_nonzero\":%zu,\"r0_fnv1a64\":\"%016llx\",\"r1_fnv1a64\":\"%016llx\"}\n",
      phase,M,w.mcap,memcmp(w.xq,expected.data(),M*32)==0?"true":"false",
      nonzero(w.xq,M*32),nonzero(w.r0,M*32*2),nonzero(w.r1,M*32*2),
      nonzero(w.limbs,M*32*4),nonzero(w.mask_limbs,M*32*4),fp(w.r0,M*32*2),fp(w.r1,M*32*2));
}
int main(int argc,char **argv) {
    if(argc!=2 || (strcmp(argv[1],"--run-synthetic") && strcmp(argv[1],"--run-synthetic-rng-error"))) return 2;
    const bool error_mode=!strcmp(argv[1],"--run-synthetic-rng-error");
    setenv("OTP_RNS_NO_VERIFY","1",1);unsetenv("OTP_RNS_DEBUG");
    printf("{\"event\":\"scope\",\"same_process_test_observer\":true,\"production_memory_access\":false,\"cpu_correction\":false,\"rng_error_mode\":%s}\n",error_mode?"true":"false");
    if(q8_init(0)) return 3;
    constexpr int K=32,N=16;
    int8_t weights[N*K];float scales[N];void *dw=nullptr;
    for(int n=0;n<N;++n) {scales[n]=(n+1)/128.f;for(int k=0;k<K;++k) weights[n*K+k]=(n*11+k*7)%31-15;}
    if(aclrtMalloc(&dw,sizeof(weights),ACL_MEM_MALLOC_HUGE_FIRST) || aclrtMemcpy(dw,sizeof(weights),weights,sizeof(weights),ACL_MEMCPY_HOST_TO_DEVICE)) {
        if(dw) aclrtFree(dw);q8_fini();return 4;
    }
    int failures=0;unsigned long long prior0=0,prior1=0;
    std::vector<unsigned char> tails[5];
    for(int step=0;step<3;++step) {
        int M=step==2?1:2;
        std::vector<float> x(M*K),out(M*N,NAN);std::vector<int8_t> expected(M*K);
        for(int m=0;m<M;++m) for(int k=0;k<K;++k) {
            int v=k?((k*13+m*17+(step==2?9:0))%127-63):127;
            x[m*K+k]=float(v);expected[m*K+k]=(int8_t)v;
        }
        fail_rng=error_mode && step==2;
        int rc=q8_linear_otp_rns_raw(x.data(),M,K,dw,weights,scales,N,out.data());
        fail_rng=0;
        int bad=0;
        if(rc==0) for(int m=0;m<M;++m) for(int n=0;n<N;++n) {
            int dot=0;for(int k=0;k<K;++k) dot+=expected[m*K+k]*weights[n*K+k];
            bad+=out[m*N+n]!=(float)(half)(dot*scales[n]);
        }
        bool ok=error_mode && step==2 ? rc!=0 && injected>0 : rc==0 && bad==0;
        failures+=!ok;
        printf("{\"event\":\"case\",\"step\":%d,\"M\":%d,\"rc\":%d,\"output_mismatches\":%d,\"injected_getrandom_EIO\":%d,\"pass\":%s}\n",step,M,rc,bad,injected,ok?"true":"false");
        if(!ok) break;
        observe(step==0?"first_success":step==1?"second_success":error_mode?"rng_error_return":"small_success",M,expected);
        RnsWorkspace &w=g_rns_ws[0];
        if(step==0) {prior0=fp(w.r0,128);prior1=fp(w.r1,128);}
        if(step==1) {
            printf("{\"event\":\"fresh_masks\",\"r0_changed\":%s,\"r1_changed\":%s}\n",prior0!=fp(w.r0,128)?"true":"false",prior1!=fp(w.r1,128)?"true":"false");
            const unsigned char *p[]={(unsigned char*)w.xq,(unsigned char*)w.r0,(unsigned char*)w.r1,(unsigned char*)w.limbs,(unsigned char*)w.mask_limbs};
            size_t lens[]={32,64,64,128,128};
            for(int i=0;i<5;++i) tails[i].assign(p[i]+lens[i],p[i]+2*lens[i]);
        }
        if(step==2) {
            const char *names[]={"xq","r0","r1","limbs","mask_limbs"};
            const unsigned char *p[]={(unsigned char*)w.xq,(unsigned char*)w.r0,(unsigned char*)w.r1,(unsigned char*)w.limbs,(unsigned char*)w.mask_limbs};
            for(int i=0;i<5;++i) {size_t n=tails[i].size();printf("{\"event\":\"unused_tail\",\"buffer\":\"%s\",\"bytes\":%zu,\"unchanged\":%s,\"nonzero_bytes\":%zu}\n",names[i],n,memcmp(p[i]+n,tails[i].data(),n)==0?"true":"false",nonzero(p[i]+n,n));}
        }
    }
    RnsWorkspace &w=g_rns_ws[0];size_t mk=w.mcap*w.kcap,mn=w.mcap*w.ncap;
    Tracked list[]={{"xq",w.xq,mk},{"r0",w.r0,mk*2},{"r1",w.r1,mk*2},{"xs",w.xs,w.mcap*4},{"limbs",w.limbs,mk*4},{"mask_limbs",w.mask_limbs,mk*4},{"y",w.y,mn*16},{"plain",w.plain,mn*4},{"corr0",w.corr0,mn*8},{"corr1",w.corr1,mn*8}};
    for(auto t:list) if(t.ptr) tracked[tracked_count++]=t;
    failures+=aclrtMemset(dw,sizeof(weights),0,sizeof(weights))!=0;
    failures+=aclrtFree(dw)!=0;
    q8_fini();
    bool cleared=true;for(auto t:tracked) cleared &= t.ptr==nullptr;
    printf("{\"event\":\"summary\",\"failed_cases_or_cleanup\":%d,\"tracked_buffers\":%d,\"observed_frees\":%d,\"nonzero_at_free_buffers\":%d,\"all_tracked_freed\":%s,\"workspace_struct_zero\":%s}\n",failures,tracked_count,freed_count,nonzero_frees,cleared?"true":"false",nonzero(&g_rns_ws[0],sizeof(g_rns_ws[0]))==0?"true":"false");
    return failures || !cleared ? 1:0;
}
