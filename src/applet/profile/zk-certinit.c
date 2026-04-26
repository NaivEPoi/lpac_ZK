#include "zk-certinit.h"
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

static const char *opt_string = "p:h?";

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

static int random_bytes(uint8_t *out, size_t len) {
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        return -1;
    }
    if (fread(out, 1, len, fp) != len) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

static int applet_main(int argc, char **argv) {
    int fret;
    int opt;
    const char *error_function_name = NULL;
    _cleanup_free_ char *error_detail = NULL;
    char *pca_addr = NULL;
    uint8_t session_key_seed[32];
    uint8_t *pseudonym_certificate = NULL;
    int pseudonym_certificate_len = 0;
    _cleanup_free_ char *pseudonym_certificate_b64 = NULL;
    struct es10b_zk_cert_init_result cert_init;

    memset(&cert_init, 0, sizeof(cert_init));

    while ((opt = getopt(argc, argv, opt_string)) != -1) {
        switch (opt) {
        case 'p':
            pca_addr = strdup(optarg);
            break;
        case 'h':
        case '?':
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("\t -p PCA Server Address (required)\n");
            printf("\t -h This help info\n");
            return -1;
        default:
            break;
        }
    }

    if (!pca_addr) {
        error_function_name = "pca_addr";
        error_detail = strdup("required");
        goto err;
    }
    if (random_bytes(session_key_seed, sizeof(session_key_seed)) < 0) {
        error_function_name = "random_bytes";
        goto err;
    }

    jprint_progress("es10b_zk_cert_init_request", NULL);
    if (es10b_zk_cert_init_request_r(&euicc_ctx, &cert_init, session_key_seed,
                                     sizeof(session_key_seed))
        < 0) {
        error_function_name = "es10b_zk_cert_init_request";
        goto err;
    }

    jprint_progress("es12p_cert_init_request", pca_addr);
    if (es12p_cert_init_request(&euicc_ctx, pca_addr, cert_init.userPublicKey,
                                cert_init.bindingSignature,
                                cert_init.credentialBindingHash,
                                &pseudonym_certificate_b64)
        < 0) {
        error_function_name = "es12p_cert_init_request";
        goto err;
    }
    if (b64_decode_alloc(pseudonym_certificate_b64, &pseudonym_certificate,
                         &pseudonym_certificate_len)
        < 0) {
        error_function_name = "pseudonymCertificate";
        goto err;
    }

    jprint_progress("es10b_zk_cert_install", NULL);
    if (es10b_zk_cert_install_r(&euicc_ctx, pseudonym_certificate,
                                (uint32_t)pseudonym_certificate_len)
        < 0) {
        error_function_name = "es10b_zk_cert_install";
        goto err;
    }

    jprint_success(NULL);
    fret = 0;
    goto exit;

err:
    fret = -1;
    jprint_error(error_function_name, error_detail);
exit:
    free(pca_addr);
    free(pseudonym_certificate);
    es10b_zk_cert_init_result_free(&cert_init);
    euicc_http_cleanup(&euicc_ctx);
    return fret;
}

struct applet_entry applet_profile_zk_certinit = {
    .name = "zk-certinit",
    .main = applet_main,
};
