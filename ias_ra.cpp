/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */



#include "service_provider.h"
#include "sample_libcrypto.h"
#include "ecp.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <string.h>
#include "ias_ra.h"

//This whole file is used as simulation of the interfaces to be
// delivered an attestation server. 


#define UNUSED(expr) do { (void)(expr); } while (0)

#if !defined(SWAP_ENDIAN_DW)
    #define SWAP_ENDIAN_DW(dw)	((((dw) & 0x000000ff) << 24)                \
    | (((dw) & 0x0000ff00) << 8)                                            \
    | (((dw) & 0x00ff0000) >> 8)                                            \
    | (((dw) & 0xff000000) >> 24))
#endif
#if !defined(SWAP_ENDIAN_32B)
    #define SWAP_ENDIAN_32B(ptr)                                            \
{\
    unsigned int temp = 0;                                                  \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[0]);                       \
    ((unsigned int*)(ptr))[0] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[7]);  \
    ((unsigned int*)(ptr))[7] = temp;                                       \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[1]);                       \
    ((unsigned int*)(ptr))[1] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[6]);  \
    ((unsigned int*)(ptr))[6] = temp;                                       \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[2]);                       \
    ((unsigned int*)(ptr))[2] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[5]);  \
    ((unsigned int*)(ptr))[5] = temp;                                       \
    temp = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[3]);                       \
    ((unsigned int*)(ptr))[3] = SWAP_ENDIAN_DW(((unsigned int*)(ptr))[4]);  \
    ((unsigned int*)(ptr))[4] = temp;                                       \
}
#endif

// This is the ECDSA NIST P-256 private key used to sign platform_info_blob.
// This private
// key and the public key in SDK untrusted KElibrary should be a temporary key
// pair. For production parts an attestation server will sign the platform_info_blob with the
// production private key and the SDK untrusted KE library will have the public
// key for verifcation.

static const sample_ec256_private_t g_rk_priv_key =
{{
    0x63,0x2c,0xd4,0x02,0x7a,0xdc,0x56,0xa5,
    0x59,0x6c,0x44,0x3e,0x43,0xca,0x4e,0x0b,
    0x58,0xcd,0x78,0xcb,0x3c,0x7e,0xd5,0xb9,
    0xf2,0x91,0x5b,0x39,0x0d,0xb3,0xb5,0xfb
}};

static sample_spid_t g_sim_spid = {"Service X"};



static const uint8_t EPID_GROUP_CERT[] = {
	0x00, 0x00, 0x00, 0x0B, 0xB3, 0x6F, 0xFF, 0x81, 0xE2, 0x1B, 0x17, 0xEB,
	0x3D, 0x75, 0x3D, 0x61, 0x7E, 0x27, 0xB0, 0xCB, 0xD0, 0x6D, 0x8F, 0x9D,
	0x64, 0xCE, 0xE3, 0xCE, 0x43, 0x4C, 0x62, 0xFD, 0xB5, 0x80, 0xE0, 0x99,
	0x3A, 0x07, 0x56, 0x80, 0xE0, 0x88, 0x59, 0xA4, 0xFD, 0xB5, 0xB7, 0x9D,
	0xE9, 0x4D, 0xAE, 0x9C, 0xEE, 0x3D, 0x66, 0x42, 0x82, 0x45, 0x7E, 0x7F,
	0xD8, 0x69, 0x3E, 0xA1, 0x74, 0xF4, 0x59, 0xEE, 0xD2, 0x74, 0x2E, 0x9F,
	0x63, 0xC2, 0x51, 0x8E, 0xD5, 0xDB, 0xCA, 0x1C, 0x54, 0x74, 0x10, 0x7B,
	0xDC, 0x99, 0xED, 0x42, 0xD5, 0x5B, 0xA7, 0x04, 0x29, 0x66, 0x61, 0x63,
	0xBC, 0xDD, 0x7F, 0xE1, 0x76, 0x5D, 0xC0, 0x6E, 0xE3, 0x14, 0xAC, 0x72,
	0x48, 0x12, 0x0A, 0xA6, 0xE8, 0x5B, 0x08, 0x7B, 0xDA, 0x3F, 0x51, 0x7D,
	0xDE, 0x4C, 0xEA, 0xCB, 0x93, 0xA5, 0x6E, 0xCC, 0xE7, 0x8E, 0x10, 0x84,
	0xBD, 0x19, 0x5A, 0x95, 0xE2, 0x0F, 0xCA, 0x1C, 0x50, 0x71, 0x94, 0x51,
	0x40, 0x1B, 0xA5, 0xB6, 0x78, 0x87, 0x53, 0xF6, 0x6A, 0x95, 0xCA, 0xC6,
	0x8D, 0xCD, 0x36, 0x88, 0x07, 0x28, 0xE8, 0x96, 0xCA, 0x78, 0x11, 0x5B,
	0xB8, 0x6A, 0xE7, 0xE5, 0xA6, 0x65, 0x7A, 0x68, 0x15, 0xD7, 0x75, 0xF8,
	0x24, 0x14, 0xCF, 0xD1, 0x0F, 0x6C, 0x56, 0xF5, 0x22, 0xD9, 0xFD, 0xE0,
	0xE2, 0xF4, 0xB3, 0xA1, 0x90, 0x21, 0xA7, 0xE0, 0xE8, 0xB3, 0xC7, 0x25,
	0xBC, 0x07, 0x72, 0x30, 0x5D, 0xEE, 0xF5, 0x6A, 0x89, 0x88, 0x46, 0xDD,
	0x89, 0xC2, 0x39, 0x9C, 0x0A, 0x3B, 0x58, 0x96, 0x57, 0xE4, 0xF3, 0x3C,
	0x79, 0x51, 0x69, 0x36, 0x1B, 0xB6, 0xF7, 0x05, 0x5D, 0x0A, 0x88, 0xDB,
	0x1F, 0x3D, 0xEA, 0xA2, 0xBA, 0x6B, 0xF0, 0xDA, 0x8E, 0x25, 0xC6, 0xAD,
	0x83, 0x7D, 0x3E, 0x31, 0xEE, 0x11, 0x40, 0xA9
};




/* This is the x component of production public key
used for EC-DSA verify for EPID Signing key. */
const uint8_t g_sgx_isk_pubkey_x[] = {
	0x26, 0x9c, 0x10, 0x82, 0xe3, 0x5a, 0x78, 0x26,
	0xee, 0x2e, 0xcc, 0x0d, 0x29, 0x50, 0xc9, 0xa4,
	0x7a, 0x21, 0xdb, 0xcf, 0xa7, 0x6a, 0x95, 0x92,
	0xeb, 0x2f, 0xb9, 0x24, 0x89, 0x88, 0xbd, 0xce
};
/* This is the y component of production public key
used for EC-DSA verify. Same as upper. */
const uint8_t g_sgx_isk_pubkey_y[] = {
	0xb8, 0xe0, 0xf2, 0x41, 0xc3, 0xe5, 0x35, 0x52,
	0xbc, 0xef, 0x9c, 0x04, 0x02, 0x06, 0x48, 0xa5,
	0x76, 0x10, 0x1b, 0xa4, 0x28, 0xe4, 0x8e, 0xa9,
	0xcf, 0xba, 0x41, 0x75, 0xdf, 0x06, 0x50, 0x62
};



// Simulates the attestation server function for verifying the quote produce by
// the ISV enclave. It doesn't decrypt or verify the quote in
// the simulation.  Just produces the attestaion verification
// report with the platform info blob.
//
// @param p_isv_quote Pointer to the quote generated by the ISV
//                    enclave.
// @param pse_manifest Pointer to the PSE manifest if used.
// @param p_attestation_verification_report Pointer the outputed
//                                          verification report.
//
// @return int

int ias_verify_attestation_evidence(
    sample_quote_t *p_isv_quote,
    uint8_t* pse_manifest,
    ias_att_report_t* p_attestation_verification_report)
{
    int ret = 0;
    sample_ecc_state_handle_t ecc_state = NULL;

    //unused parameters
    UNUSED(pse_manifest);

    if((NULL == p_isv_quote) ||
        (NULL == p_attestation_verification_report))
    {
        return -1;
    }
    //Decrypt the Quote signature and verify.

    p_attestation_verification_report->id = 0x12345678;
    p_attestation_verification_report->status = IAS_QUOTE_OK;
    p_attestation_verification_report->revocation_reason =
        IAS_REVOC_REASON_NONE;
    p_attestation_verification_report->info_blob.sample_epid_group_status =
        0 << IAS_EPID_GROUP_STATUS_REVOKED_BIT_POS
        | 0 << IAS_EPID_GROUP_STATUS_REKEY_AVAILABLE_BIT_POS;
    p_attestation_verification_report->info_blob.sample_tcb_evaluation_status =
        0 << IAS_TCB_EVAL_STATUS_CPUSVN_OUT_OF_DATE_BIT_POS
        | 0 << IAS_TCB_EVAL_STATUS_ISVSVN_OUT_OF_DATE_BIT_POS;
    p_attestation_verification_report->info_blob.pse_evaluation_status =
        0 << IAS_PSE_EVAL_STATUS_ISVSVN_OUT_OF_DATE_BIT_POS
        | 0 << IAS_PSE_EVAL_STATUS_EPID_GROUP_REVOKED_BIT_POS
        | 0 << IAS_PSE_EVAL_STATUS_PSDASVN_OUT_OF_DATE_BIT_POS
        | 0 << IAS_PSE_EVAL_STATUS_SIGRL_OUT_OF_DATE_BIT_POS
        | 0 << IAS_PSE_EVAL_STATUS_PRIVRL_OUT_OF_DATE_BIT_POS;
    memset(p_attestation_verification_report->
                info_blob.latest_equivalent_tcb_psvn, 0, PSVN_SIZE);
    memset(p_attestation_verification_report->info_blob.latest_pse_isvsvn,
           0, ISVSVN_SIZE);
    memset(p_attestation_verification_report->info_blob.latest_psda_svn,
           0, PSDA_SVN_SIZE);
    memset(p_attestation_verification_report->info_blob.performance_rekey_gid,
           0, GID_SIZE);

    // @TODO: Product signing algorithm still TBD.  May be RSA2048 signing.
    // Generate the Service providers ECCDH key pair.
    do {
        ret = sample_ecc256_open_context(&ecc_state);
        if (SAMPLE_SUCCESS != ret) {
            fprintf(stderr, "\nError, cannot get ECC cotext in [%s].",
                    __FUNCTION__);
            ret = -1;
            break;
        }
        // Sign
        ret = sample_ecdsa_sign(
                (uint8_t *)&p_attestation_verification_report->
                    info_blob.sample_epid_group_status,
                sizeof(ias_platform_info_blob_t) - sizeof(sample_ec_sign256_t),
                (sample_ec256_private_t *)&g_rk_priv_key,
                (sample_ec256_signature_t *)&p_attestation_verification_report->
                    info_blob.signature,
                ecc_state);
        if (SAMPLE_SUCCESS != ret) {
            fprintf(stderr, "\nError, sign ga_gb fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        SWAP_ENDIAN_32B(p_attestation_verification_report->
                            info_blob.signature.x);
        SWAP_ENDIAN_32B(p_attestation_verification_report->
                            info_blob.signature.y);

    }while (0);
    if (ecc_state) {
        sample_ecc256_close_context(ecc_state);
    }
    p_attestation_verification_report->pse_status = IAS_PSE_OK;

    // For now, don't simulate the policy reports.
    p_attestation_verification_report->policy_report_size = 0;
    return(ret);
}


// Simulates retrieving the SIGRL for upon the SP request. 
//
// @param gid Group ID for the EPID key.
// @param p_sig_rl_size Pointer to the output value of the full
//                      SIGRL size in bytes. (including the
//                      signature).
// @param p_sig_rl Pointer to the output of the SIGRL.
//
// @return int

int ias_get_sigrl(
    const sample_epid_group_id_t gid,
    uint32_t *p_sig_rl_size,
    uint8_t **p_sig_rl)
{
    int ret = 0;

    UNUSED(gid);

    do {

        if (NULL == p_sig_rl || NULL == p_sig_rl_size) {
            ret = -1;
            break;
        }
        *p_sig_rl_size = 0;
        *p_sig_rl = NULL;
        // we should try to get sig_rl from an attestation server
        break;
    }while (0);

    return(ret);
}


// Used to simulate the enrollment function of an attestation server.  It only
// gives back the SPID right now. In production, the enrollment
// occurs out of context from an attestation attempt and only
// occurs once.
//
//
// @param sp_credentials
// @param p_spid
// @param p_authentication_token
//
// @return int

int ias_enroll(
    int sp_credentials,
    sample_spid_t *p_spid,
    int *p_authentication_token)
{
    UNUSED(sp_credentials);
    UNUSED(p_authentication_token);

    if (NULL != p_spid) {
        memcpy_s(p_spid, sizeof(sample_spid_t), &g_sim_spid,
                 sizeof(sample_spid_t));
    } else {
        return(1);
    }
    return(0);
}


