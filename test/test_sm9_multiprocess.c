#include "sm9.h"
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "debug.h"
#define count 10000

// pairing多进程使用的全局变量
fp12_t r_arr[count];
g1_t g1_arr[count];
ep2_t Ppub_arr[count];

// sign和verify多进程使用的全局变量
void init_none(){

}

void init_pairing_input(){
    g1_t g1;
    ep2_t Ppub;
    fp12_t r;

    g1_null(g1);
    g1_new(g1);
    g1_get_gen(g1);

    ep2_null(Ppub);
    ep2_new(Ppub);

    fp12_null(r);
    fp12_new(r);

    char x0[] = "29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32";
    char x1[] = "9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408";
    char y0[] = "41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D";
    char y1[] = "69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25";
    char z0[] = "1";
    char z1[] = "0";

    fp_read_str(Ppub->x[0], x0, strlen(x0), 16);
    fp_read_str(Ppub->x[1], x1, strlen(x1), 16);
    fp_read_str(Ppub->y[0], y0, strlen(y0), 16);
    fp_read_str(Ppub->y[1], y1, strlen(y1), 16);
    fp_read_str(Ppub->z[0], z0, strlen(z0), 16);
    fp_read_str(Ppub->z[1], z1, strlen(z1), 16);

    for (size_t i = 0; i < count; i++)
    {
        fp12_null(r_arr[i]);
        fp12_new(r_arr[i]);

        g1_null(g1_arr[i]);
        g1_new(g1_arr[i]);
        g1_copy(g1_arr[i], g1);

        ep2_null(Ppub_arr[i]);
        ep2_new(Ppub_arr[i]);
        ep2_copy(Ppub_arr[i], Ppub);
    }
}

void run_pairing(int pid, size_t start, size_t end)
{
    printf("pid %d run [%d, %d]\n", pid, start, end);
#if 1
    for (size_t i = start; i < end; i++)
    {
        sm9_pairing_fast(r_arr[i], Ppub_arr[i], g1_arr[i]);
    }
#endif

#if 0
    // 使用局部变量，性能好像并没有提升...
    g1_t g1;
	ep2_t Ppub;
	fp12_t r;

	g1_null(g1);
	g1_new(g1);
	g1_get_gen(g1);

	ep2_null(Ppub);
	ep2_new(Ppub);

    fp12_null(r);
	fp12_new(r);

	char x0[] = "29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32";
	char x1[] = "9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408";
	char y0[] = "41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D";
	char y1[] = "69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25";
	char z0[] = "1";
	char z1[] = "0";

	fp_read_str(Ppub->x[0], x0, strlen(x0), 16);
	fp_read_str(Ppub->x[1], x1, strlen(x1), 16);
	fp_read_str(Ppub->y[0], y0, strlen(y0), 16);
	fp_read_str(Ppub->y[1], y1, strlen(y1), 16);
	fp_read_str(Ppub->z[0], z0, strlen(z0), 16);
	fp_read_str(Ppub->z[1], z1, strlen(z1), 16);

    for (size_t i = start; i < end; i++)
    {
        sm9_pairing_fast(r, Ppub, g1);
    }
#endif
    // 打印调试信息
    // printf("process-%d do %d jobs\n", pid, end-start);
    exit(100+pid);
}

void run_sign(int pid, size_t start, size_t end){
    const char *id = "Alice";
    // data = "Chinese IBS standard"
    uint8_t data[20] = {0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x53, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64};
    int idlen = 5;
    int datalen = 20;

    SM9_SIGN_KEY sign_key;
    SM9_SIGN_MASTER_KEY sign_master;
    SM9_SIGN_CTX ctx;
    uint8_t sig[104];
    size_t siglen;

    sign_user_key_init(&sign_key);
    sign_master_key_init(&sign_master);

    sm9_sign_master_key_extract_key(&sign_master, (char *)id, idlen, &sign_key);
    sm9_sign_init(&ctx);
    sm9_sign_update(&ctx,data, datalen);
    for (size_t i = start; i < end; i++)
    {
        sm9_sign_finish(&ctx, &sign_key, sig, &siglen);
    }
//    PERFORMANCE_TEST_NEW("RELIC SM9_signature ",sm9_sign_finish(&ctx, &sign_key, sig, &siglen));

//    sm9_verify_init(&ctx);
//    sm9_verify_update(&ctx, data, datalen);
//    PERFORMANCE_TEST_NEW("RELIC SM9_verification ",sm9_verify_finish(&ctx, sig, siglen, &sign_key,(char *)id, idlen));
//
    sign_master_key_free(&sign_master);
    sign_user_key_free(&sign_key);
//    printf("%s() ok\n", __FUNCTION__);
    exit(100+pid);
}

void run_verify(int pid, size_t start, size_t end){
    const char *id = "Alice";
    // data = "Chinese IBS standard"
    uint8_t data[20] = {0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x53, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64};
    int idlen = 5;
    int datalen = 20;

    SM9_SIGN_KEY sign_key;
    SM9_SIGN_MASTER_KEY sign_master;
    SM9_SIGN_CTX ctx;
    uint8_t sig[104];
    size_t siglen;

    sign_user_key_init(&sign_key);
    sign_master_key_init(&sign_master);

    sm9_sign_master_key_extract_key(&sign_master, (char *)id, idlen, &sign_key);
    sm9_sign_init(&ctx);
    sm9_sign_update(&ctx,data, datalen);
    sm9_sign_finish(&ctx, &sign_key, sig, &siglen);

    sm9_verify_init(&ctx);
    sm9_verify_update(&ctx, data, datalen);
    for (size_t i = start; i < end; i++)
    {
        sm9_verify_finish(&ctx, sig, siglen, &sign_key,(char *)id, idlen);
    }
//    PERFORMANCE_TEST_NEW("RELIC SM9_verification ",sm9_verify_finish(&ctx, sig, siglen, &sign_key,(char *)id, idlen));

    sign_master_key_free(&sign_master);
    sign_user_key_free(&sign_key);
//    printf("%s() ok\n", __FUNCTION__);
    exit(100+pid);
}

void run_enc(int pid, size_t start, size_t end) {
    SM9_ENC_MASTER_KEY msk;
    SM9_ENC_KEY enc_key;

    //enc_master_key_init(&msk);
    //enc_user_key_init(&enc_key);

    ep_null(enc_key.Ppube);
    ep_new(enc_key.Ppube);
    ep2_null(enc_key.de);
    ep2_new(enc_key.de);

    uint8_t out[1000] = {0};
    size_t outlen = 0;
    int j = 1;

    //Chinese IBE standard
    uint8_t data[20] = {0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x45, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64};
    uint8_t dec[20] = {0};
    size_t declen = 20;

    //Bob
    uint8_t IDB[3] = {0x42, 0x6F, 0x62};

    enc_master_key_init(&msk);

    if (sm9_enc_master_key_extract_key(&msk, (char *)IDB, sizeof(IDB), &enc_key) < 0) goto err; ++j;

    // 先判断能否正确加密
    if (sm9_encrypt(&msk, (char *)IDB, sizeof(IDB), data, sizeof(data), out, &outlen) < 0) goto err; ++j;
    // 重复加密测试性能
    for (size_t i = start; i < end; i++)
    {
        sm9_encrypt(&msk, (char *)IDB, sizeof(IDB), data, sizeof(data), out, &outlen);
    }
    //
//    PERFORMANCE_TEST_NEW("RELIC SM9_encrypt ",sm9_encrypt(&msk, (char *)IDB, sizeof(IDB), data, sizeof(data), out, &outlen) );
    //format_bytes(stdout, 0, 0, "ciphertext", out, outlen);
//    PERFORMANCE_TEST_NEW("RELIC SM9_decrypt ",sm9_decrypt(&enc_key, (char *)IDB, sizeof(IDB), out, outlen, dec, &declen) );
    // if (sm9_decrypt(&enc_key, (char *)IDB, sizeof(IDB), out, outlen, dec, &declen) < 0) goto err; ++j;
//    if (memcmp(data, dec, sizeof(data)) != 0) goto err; ++j;
//    //format_bytes(stdout, 0, 0, "plaintext", dec, declen);
//    printf("%s() ok\n", __FUNCTION__);

    ep_free(msk.Ppube);
    bn_free(msk.ke);
    ep_free(enc_key.Ppube);
    ep2_free(enc_key.de);
    //enc_master_key_free(&msk);
    //enc_user_key_free(&enc_key);

    exit(100+pid);

    err:
    ep_free(msk.Ppube);
    bn_free(msk.ke);
    ep_free(enc_key.Ppube);
    ep2_free(enc_key.de);
    //enc_master_key_free(&msk);
    //enc_user_key_free(&enc_key);
    printf("%s test %d failed\n", __FUNCTION__, j);
    error_print();

}

void run_dec(int pid, size_t start, size_t end) {
    SM9_ENC_MASTER_KEY msk;
    SM9_ENC_KEY enc_key;

    //enc_master_key_init(&msk);
    //enc_user_key_init(&enc_key);

    ep_null(enc_key.Ppube);
    ep_new(enc_key.Ppube);
    ep2_null(enc_key.de);
    ep2_new(enc_key.de);

    uint8_t out[1000] = {0};
    size_t outlen = 0;
    int j = 1;

    //Chinese IBE standard
    uint8_t data[20] = {0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x45, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64};
    uint8_t dec[20] = {0};
    size_t declen = 20;

    //Bob
    uint8_t IDB[3] = {0x42, 0x6F, 0x62};

    enc_master_key_init(&msk);

    if (sm9_enc_master_key_extract_key(&msk, (char *)IDB, sizeof(IDB), &enc_key) < 0) goto err; ++j;

    // 先判断能否正确加密
    if (sm9_encrypt(&msk, (char *)IDB, sizeof(IDB), data, sizeof(data), out, &outlen) < 0) goto err; ++j;
    // 先判断能否正确解密
    if (sm9_decrypt(&enc_key, (char *)IDB, sizeof(IDB), out, outlen, dec, &declen) < 0) goto err; ++j;
    // 重复解密测试性能
    for (size_t i = start; i < end; i++)
    {
        sm9_decrypt(&enc_key, (char *)IDB, sizeof(IDB), out, outlen, dec, &declen);
    }
    ep_free(msk.Ppube);
    bn_free(msk.ke);
    ep_free(enc_key.Ppube);
    ep2_free(enc_key.de);
    //enc_master_key_free(&msk);
    //enc_user_key_free(&enc_key);

    exit(100+pid);

    err:
    ep_free(msk.Ppube);
    bn_free(msk.ke);
    ep_free(enc_key.Ppube);
    ep2_free(enc_key.de);
    //enc_master_key_free(&msk);
    //enc_user_key_free(&enc_key);
    printf("%s test %d failed\n", __FUNCTION__, j);
    error_print();

}

// 参数分别为：线程数、初始化输入参数、运行函数
int test_processes(int num_processes, void (*init_input)(void), void (*run)(int, size_t, size_t)){

    // 计算每个线程需要完成的工作量
    size_t process_do_num = count / num_processes + 1;

    // 初始化SM9相关参数
    sm9_init();

    // 初始化输入
    init_input();

    int status, i;
    pid_t pid[num_processes], retpid;

    struct timeval t0, t1;

    gettimeofday(&t0, NULL);

    for (i = 0; i < num_processes; i++)
    {
        if ((pid[i] = fork()) == 0)
        {
            // 计算每个子进程分配到的任务区间
            size_t start = i * process_do_num;
            size_t end = start + process_do_num;
            if(end > count) {
                end = count;
            }
            run(i, start, end);
        }
    }

    // 进程同步
    i = 0;
    while ((retpid = waitpid(pid[i++], &status, 0)) > 0)
    {
        if (WIFEXITED(status)){
            // 打印调试信息
            // printf("child %d terminated normally with exit status=%d\n", retpid, WEXITSTATUS(status));
        }else{
            printf("child %d terminated abnormally\n", retpid);
        }
    }
    gettimeofday(&t1, NULL);
    float total_time = t1.tv_sec - t0.tv_sec + 1E-6 * (t1.tv_usec - t0.tv_usec);
    printf("%d processes do %d jobs in %.2f seconds, per second do %.2f times\n", num_processes, count, total_time, count/total_time);
    return 0;
}


int main(int argc, char *argv[]) {
    if (core_init() != RLC_OK) {
        core_clean();
        return 1;
    }

    if (pc_param_set_any() != RLC_OK) {
        RLC_THROW(ERR_NO_CURVE);
        core_clean();
        return 0;
    }
#if 0
    printf("test_multiprocess_pairing: \n");
    test_processes(64, init_pairing_input, run_pairing);
    test_processes(3, init_pairing_input, run_pairing);
    test_processes(4, init_pairing_input, run_pairing);
    test_processes(8, init_pairing_input, run_pairing);
    test_processes(12, init_pairing_input, run_pairing);
#endif
#if 0
    printf("test_multiprocess_sign: \n");
    test_processes(32, init_none, run_sign);
    test_processes(3, init_none, run_sign);
    test_processes(4, init_none, run_sign);
    test_processes(8, init_none, run_sign);
    test_processes(12, init_none, run_sign);
    test_processes(16, init_none, run_sign);
#endif
#if 0
    printf("test_multiprocess_verify: \n");
    test_processes(2, init_none, run_verify);
    test_processes(3, init_none, run_verify);
    test_processes(4, init_none, run_verify);
    test_processes(8, init_none, run_verify);
    test_processes(12, init_none, run_verify);
    test_processes(16, init_none, run_verify);
#endif
#if 0
    printf("test_multiprocess_enc: \n");
    test_processes(2, init_none, run_enc);
    test_processes(3, init_none, run_enc);
    test_processes(4, init_none, run_enc);
    test_processes(8, init_none, run_enc);
    test_processes(12, init_none, run_enc);
    test_processes(16, init_none, run_enc);
    test_processes(24, init_none, run_enc);
    test_processes(32, init_none, run_enc);
#endif
#if 1
    printf("test_multiprocess_dec: \n");
    test_processes(2, init_none, run_dec);
    test_processes(3, init_none, run_dec);
    test_processes(4, init_none, run_dec);
    test_processes(8, init_none, run_dec);
    test_processes(12, init_none, run_dec);
    test_processes(16, init_none, run_dec);
    test_processes(24, init_none, run_dec);
    test_processes(32, init_none, run_dec);
#endif
    core_clean();

    return 0;
}
