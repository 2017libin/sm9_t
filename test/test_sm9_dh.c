/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sm9.h"
#include "gmssl/error.h"
#include "debug.h"
#include <malloc.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>

int test_sm9_exchange() {

	SM9_ENC_MASTER_KEY msk;
	SM9_ENC_KEY alice_key;
    SM9_ENC_KEY bob_key;

    ep_t Ra;
    ep_null(Ra);
    ep_new(Ra);
    ep_t Rb;
    ep_null(Rb);
    ep_new(Rb);

    bn_t ra;
    bn_null(ra);
    bn_new(ra);

    fp12_t g1,g2,g3;
    fp12_null(g1);
	fp12_new(g1);
	fp12_null(g3);
	fp12_new(g3);
	fp12_null(g2);
	fp12_new(g2);

    char ke[] = "2E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F";
    //enc_master_key_init(&msk);
    enc_master_key_read(&msk,ke,strlen(ke),16);
    enc_user_key_init(&bob_key);
    enc_user_key_init(&alice_key);

	int j = 1;

    uint8_t kbuf[16] = {0};
    uint8_t sa[32];
    uint8_t sb[32];
    int salen = 32;
    int sblen = 32;
    int klen = sizeof(kbuf);
    uint8_t output[65];
    int outlen = 65;

    //Alice
    uint8_t IDA[5] = {0x41,0x6C,0x69,0x63,0x65};
	//Bob
	uint8_t IDB[3] = {0x42, 0x6F, 0x62};

	if (sm9_exch_master_key_extract_key(&msk, (char *)IDB, sizeof(IDB), &bob_key) < 0) goto err; ++j;
	if (sm9_exch_master_key_extract_key(&msk, (char *)IDA, sizeof(IDA), &alice_key) < 0) goto err; ++j;
    sm9_exchange_A1(&alice_key, (char *)IDB, sizeof(IDB),Ra,ra);
    sm9_exchange_B1(&bob_key,g1,g2,g3,Ra,Rb,(char *)IDA, sizeof(IDA),(char *)IDB, sizeof(IDB),klen,kbuf,sblen,sb);
    printf("\nSK_B :");
    print_bytes(kbuf,klen);
    sm9_exchange_A2(&alice_key,Ra,Rb,ra,(char *)IDA, sizeof(IDA),(char *)IDB, sizeof(IDB),klen,kbuf,salen,sa,sblen,sb);
    printf("\nSK_A :");
    print_bytes(kbuf,klen);
    sm9_exchange_B2(g1,g2,g3,Ra,Rb,(char *)IDA, sizeof(IDA),(char *)IDB, sizeof(IDB),salen,sa);

/*
    char alicetempo[] = "alicetempo.bin";
    char bobtempo[] = "bobtempo.bin";
    char alicehash[] = "alicehash.bin";
    char bobhash[] = "bobhash.bin";

    ep_write_bin(output,outlen,Ra,0);
    write_file(alicetempo,output,outlen);
    ep_write_bin(output,outlen,Rb,0);
    write_file(bobtempo,output,outlen);

    write_file(alicehash,sa,salen);
    write_file(bobhash,sb,sblen);
*/

    enc_master_key_free(&msk);
    enc_user_key_free(&bob_key);
    enc_user_key_free(&alice_key);
    ep_free(Ra);
    ep_free(Rb);
    bn_free(ra);
    fp12_free(g3);
    fp12_free(g2);
    fp12_free(g1);
	return 1;
err:
    enc_master_key_free(&msk);
    enc_user_key_free(&bob_key);
    enc_user_key_free(&alice_key);
    ep_free(Ra);
    ep_free(Rb);
    bn_free(ra);
    fp12_free(g3);
    fp12_free(g2);
    fp12_free(g1);
    //enc_master_key_free(&msk);
    //enc_user_key_free(&enc_key);
	printf("%s test %d failed\n", __FUNCTION__, j);
	error_print();
	return -1;
}


int main(){
    
    if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (pc_param_set_any() != RLC_OK) {
		RLC_THROW(ERR_NO_CURVE);
		core_clean();
		return 0;
	}

    test_sm9_exchange();
    
    core_clean();
    return 0;
}