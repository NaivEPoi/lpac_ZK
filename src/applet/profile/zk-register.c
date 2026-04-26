#include "zk-register.h"
#include "main.h"

#include <euicc/base64.h>
#include <euicc/es10b.h>
#include <euicc/es12p.h>
#include <lpac/utils.h>

#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *opt_string = "n:h?";

static int b64_decode_alloc(const char *b64, uint8_t **out, int *out_len) {
    int alloc_len;

    *out = NULL;
    *out_len = 0;
    alloc_len = euicc_base64_decode_len(b64);
    if (alloc_len <= 0) {
        return -1;
    }
    *out = malloc((size_t)alloc_len);
    if (!*out) {
        return -1;
    }
    *out_len = euicc_base64_decode(*out, b64);
    if (*out_len < 0) {
        free(*out);
        *out = NULL;
        *out_len = 0;
        return -1;
    }
    return 0;
}

static int applet_main(int argc, char **argv) {
    int fret;
    int opt;
    const char *error_function_name = NULL;
    _cleanup_free_ char *error_detail = NULL;
    char *mno_addr = NULL;
    uint8_t *mno_nonce_commitment = NULL;
    int mno_nonce_commitment_len = 0;
    uint8_t *mno_partial_signature = NULL;
    int mno_partial_signature_len = 0;
    _cleanup_free_ char *mno_partial_signature_b64 = NULL;
    struct es12p_register_challenge_result mno_challenge;
    struct es10b_zk_register_challenge_result euicc_challenge;

    memset(&mno_challenge, 0, sizeof(mno_challenge));
    memset(&euicc_challenge, 0, sizeof(euicc_challenge));

    while ((opt = getopt(argc, argv, opt_string)) != -1) {
        switch (opt) {
        case 'n':
            mno_addr = strdup(optarg);
            break;
        case 'h':
        case '?':
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("\t -n MNO Server Address (required)\n");
            printf("\t -h This help info\n");
            return -1;
        default:
            break;
        }
    }

    if (!mno_addr) {
        error_function_name = "mno_addr";
        error_detail = strdup("required");
        goto err;
    }

    jprint_progress("es12p_register_challenge", mno_addr);
    if (es12p_register_challenge(&euicc_ctx, mno_addr, &mno_challenge) < 0) {
        error_function_name = "es12p_register_challenge";
        goto err;
    }
    if (b64_decode_alloc(mno_challenge.mnoNonceCommitment, &mno_nonce_commitment,
                         &mno_nonce_commitment_len)
        < 0) {
        error_function_name = "mnoNonceCommitment";
        goto err;
    }

    jprint_progress("es10b_zk_register_challenge", NULL);
    if (es10b_zk_register_challenge_r(&euicc_ctx, &euicc_challenge, mno_nonce_commitment,
                                      (uint32_t)mno_nonce_commitment_len)
        < 0) {
        error_function_name = "es10b_zk_register_challenge";
        goto err;
    }

    jprint_progress("es12p_register_credential", mno_addr);
    if (es12p_register_credential(&euicc_ctx, mno_addr, mno_challenge.requestId,
                                  euicc_challenge.blindedEligibilityChallenge,
                                  euicc_challenge.deviceAuthSignature,
                                  &mno_partial_signature_b64)
        < 0) {
        error_function_name = "es12p_register_credential";
        goto err;
    }
    if (b64_decode_alloc(mno_partial_signature_b64, &mno_partial_signature,
                         &mno_partial_signature_len)
        < 0) {
        error_function_name = "mnoPartialSignature";
        goto err;
    }

    jprint_progress("es10b_zk_register_credential", NULL);
    if (es10b_zk_register_credential_r(&euicc_ctx, mno_partial_signature,
                                       (uint32_t)mno_partial_signature_len)
        < 0) {
        error_function_name = "es10b_zk_register_credential";
        goto err;
    }

    jprint_success(NULL);
    fret = 0;
    goto exit;

err:
    fret = -1;
    jprint_error(error_function_name, error_detail);
exit:
    free(mno_addr);
    free(mno_nonce_commitment);
    free(mno_partial_signature);
    es12p_register_challenge_result_free(&mno_challenge);
    es10b_zk_register_challenge_result_free(&euicc_challenge);
    euicc_http_cleanup(&euicc_ctx);
    return fret;
}

struct applet_entry applet_profile_zk_register = {
    .name = "zk-register",
    .main = applet_main,
};
