#include "download.h"
#include "main.h"

#include <euicc/es10a.h>
#include <euicc/es10b.h>
#include <euicc/es8p.h>
#include <euicc/es9p.h>
#include <euicc/base64.h>
#include <euicc/derutil.h>
#include <euicc/euicc.private.h>
#include <euicc/tostr.h>
#include <lpac/utils.h>

#include <ctype.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *opt_string = "s:m:i:c:a:ph?";

static volatile int cancelled = 0;

#define CANCELPOINT() \
    if (cancelled) {  \
        goto err;     \
    }

#ifdef _WIN32
// https://stackoverflow.com/a/58244503
char *strsep(char **stringp, const char *__delim) {
    char *rv = *stringp;
    if (!rv)
        return rv;
    *stringp += strcspn(*stringp, __delim);
    if (**stringp)
        *(*stringp)++ = '\0';
    else
        *stringp = 0;
    return rv;
}
#endif

static bool is_strict_matching_id(const char *token) {
    const size_t n = strlen(token);
    for (size_t i = 0; i < n; i++) {
        if (isalnum(token[i]) || token[i] == '-')
            continue;
        return false;
    }
    return true;
}

static void sigint_handler(__attribute__((unused)) int x) { cancelled = 1; }

static int encode_der_node_to_base64(char **out, struct euicc_derutil_node *node) {
    uint8_t *der = NULL;
    uint32_t der_len = 0;
    int encoded_len;

    *out = NULL;

    if (euicc_derutil_pack_alloc(&der, &der_len, node) < 0) {
        free(der);
        return -1;
    }

    encoded_len = euicc_base64_encode_len((int)der_len);
    if (encoded_len <= 0) {
        free(der);
        return -1;
    }

    *out = malloc((size_t)encoded_len);
    if (*out == NULL) {
        free(der);
        return -1;
    }

    if (euicc_base64_encode(*out, der, (int)der_len) < 0) {
        free(der);
        free(*out);
        *out = NULL;
        return -1;
    }

    free(der);
    return 0;
}

static int placeholder_initiate_auth(struct euicc_ctx *ctx) {
    static const uint8_t dummy_txid[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    static const uint8_t server_address[] = {'s', 'm', 'd', 'p', '.', 't', 'e', 's', 't', '.', 'c', 'o', 'm'};
    static const uint8_t server_challenge[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    static const uint8_t server_signature[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    static const uint8_t euicc_ci_pk_id[] = {0x00, 0x00, 0x00, 0x00};
    char *challenge = NULL;
    int challenge_len;
    struct es10b_authenticate_server_param *param = NULL;
    struct euicc_derutil_node n_server_signed1 = {0};
    struct euicc_derutil_node n_transaction_id = {0};
    struct euicc_derutil_node n_euicc_challenge = {0};
    struct euicc_derutil_node n_server_address = {0};
    struct euicc_derutil_node n_server_challenge = {0};
    struct euicc_derutil_node n_server_signature = {0};
    struct euicc_derutil_node n_euicc_ci_pk_id = {0};
    struct euicc_derutil_node n_server_certificate = {0};

    if (ctx->http._internal.b64_euicc_challenge == NULL) {
        return -1;
    }

    param = calloc(1, sizeof(*param));
    if (param == NULL) {
        return -1;
    }

    challenge_len = euicc_base64_decode_len(ctx->http._internal.b64_euicc_challenge);
    if (challenge_len <= 0) {
        goto err;
    }

    challenge = malloc((size_t)challenge_len);
    if (challenge == NULL) {
        goto err;
    }

    if (euicc_base64_decode((unsigned char *)challenge, ctx->http._internal.b64_euicc_challenge) < 0) {
        goto err;
    }

    n_server_signed1.tag = 0x30;
    n_server_signed1.pack.child = &n_transaction_id;

    n_transaction_id.tag = 0x80;
    n_transaction_id.value = dummy_txid;
    n_transaction_id.length = (uint32_t)sizeof(dummy_txid);
    n_transaction_id.pack.next = &n_euicc_challenge;

    n_euicc_challenge.tag = 0x81;
    n_euicc_challenge.value = (const uint8_t *)challenge;
    n_euicc_challenge.length = 16;
    n_euicc_challenge.pack.next = &n_server_address;

    n_server_address.tag = 0x83;
    n_server_address.value = server_address;
    n_server_address.length = (uint32_t)sizeof(server_address);
    n_server_address.pack.next = &n_server_challenge;

    n_server_challenge.tag = 0x84;
    n_server_challenge.value = server_challenge;
    n_server_challenge.length = (uint32_t)sizeof(server_challenge);
    n_server_challenge.pack.next = &n_server_signature;

    n_server_signature.tag = 0x5F37;
    n_server_signature.value = server_signature;
    n_server_signature.length = (uint32_t)sizeof(server_signature);
    n_server_signature.pack.next = &n_euicc_ci_pk_id;

    n_euicc_ci_pk_id.tag = 0x04;
    n_euicc_ci_pk_id.value = euicc_ci_pk_id;
    n_euicc_ci_pk_id.length = (uint32_t)sizeof(euicc_ci_pk_id);
    n_euicc_ci_pk_id.pack.next = &n_server_certificate;

    n_server_certificate.tag = 0x30;

    if (encode_der_node_to_base64(&param->b64_serverSigned1, &n_server_signed1) < 0) {
        goto err;
    }

    n_server_signature.pack.next = NULL;
    if (encode_der_node_to_base64(&param->b64_serverSignature1, &n_server_signature) < 0) {
        goto err;
    }

    if (encode_der_node_to_base64(&param->b64_euiccCiPKIdToBeUsed, &n_euicc_ci_pk_id) < 0) {
        goto err;
    }

    if (encode_der_node_to_base64(&param->b64_serverCertificate, &n_server_certificate) < 0) {
        goto err;
    }

    ctx->http._internal.authenticate_server_param = param;
    free(challenge);
    return 0;

err:
    free(challenge);
    es10b_authenticate_server_param_free(param);
    free(param);
    return -1;
}

static int placeholder_authenticate_client(struct euicc_ctx *ctx) {
    static const uint8_t smdp_signature[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    struct es10b_prepare_download_param *param = NULL;
    struct euicc_derutil_node n_smdp_signed2 = {0};
    struct euicc_derutil_node n_transaction_id = {0};
    struct euicc_derutil_node n_cc_required = {0};
    struct euicc_derutil_node n_smdp_signature = {0};
    struct euicc_derutil_node n_smdp_certificate = {0};

    if (ctx->http._internal.transaction_id_bin == NULL || ctx->http._internal.transaction_id_bin_len == 0) {
        return -1;
    }

    param = calloc(1, sizeof(*param));
    if (param == NULL) {
        return -1;
    }

    n_smdp_signed2.tag = 0x30;
    n_smdp_signed2.pack.child = &n_transaction_id;

    n_transaction_id.tag = 0x80;
    n_transaction_id.value = ctx->http._internal.transaction_id_bin;
    n_transaction_id.length = ctx->http._internal.transaction_id_bin_len;
    n_transaction_id.pack.next = &n_cc_required;

    n_cc_required.tag = 0x01;
    n_cc_required.value = (const uint8_t *)"\x00";
    n_cc_required.length = 1;

    if (encode_der_node_to_base64(&param->b64_smdpSigned2, &n_smdp_signed2) < 0) {
        goto err;
    }

    n_smdp_signature.tag = 0x5F37;
    n_smdp_signature.value = smdp_signature;
    n_smdp_signature.length = (uint32_t)sizeof(smdp_signature);
    if (encode_der_node_to_base64(&param->b64_smdpSignature2, &n_smdp_signature) < 0) {
        goto err;
    }

    n_smdp_certificate.tag = 0x30;
    if (encode_der_node_to_base64(&param->b64_smdpCertificate, &n_smdp_certificate) < 0) {
        goto err;
    }

    param->b64_profileMetadata = NULL;
    ctx->http._internal.prepare_download_param = param;
    return 0;

err:
    es10b_prepare_download_param_free(param);
    free(param);
    return -1;
}

static int send_placeholder_bpp(struct euicc_ctx *ctx, struct es10b_load_bound_profile_package_result *result) {
    uint8_t *reqbuf = NULL;
    uint32_t reqlen = 0;
    uint8_t *respbuf = NULL;
    unsigned resplen = 0;
    static const uint8_t one_byte[] = {0x01};
    static const uint8_t second_byte[] = {0x02};
    static const uint8_t third_byte[] = {0x03};
    struct euicc_derutil_node n_request = {0};
    struct euicc_derutil_node n_bf23 = {0};
    struct euicc_derutil_node n_remote_op = {0};
    struct euicc_derutil_node n_transaction_id = {0};
    struct euicc_derutil_node n_control_ref = {0};
    struct euicc_derutil_node n_smdp_otpk = {0};
    struct euicc_derutil_node n_smdp_sign = {0};
    struct euicc_derutil_node n_a0 = {0};
    struct euicc_derutil_node n_87 = {0};
    struct euicc_derutil_node n_a1 = {0};
    struct euicc_derutil_node n_88 = {0};
    struct euicc_derutil_node n_a3 = {0};
    struct euicc_derutil_node n_86 = {0};
    struct euicc_derutil_node tmpnode;

    if (ctx->http._internal.transaction_id_bin == NULL || ctx->http._internal.transaction_id_bin_len == 0) {
        return -1;
    }

    n_request.tag = 0xBF36;
    n_request.pack.child = &n_bf23;

    n_bf23.tag = 0xBF23;
    n_bf23.pack.child = &n_remote_op;

    n_remote_op.tag = 0x02;
    n_remote_op.value = one_byte;
    n_remote_op.length = 1;
    n_remote_op.pack.next = &n_transaction_id;

    n_transaction_id.tag = 0x80;
    n_transaction_id.value = ctx->http._internal.transaction_id_bin;
    n_transaction_id.length = ctx->http._internal.transaction_id_bin_len;
    n_transaction_id.pack.next = &n_control_ref;

    n_control_ref.tag = 0xA6;
    n_control_ref.pack.next = &n_smdp_otpk;

    n_smdp_otpk.tag = 0x5F49;
    n_smdp_otpk.value = one_byte;
    n_smdp_otpk.length = 1;
    n_smdp_otpk.pack.next = &n_smdp_sign;

    n_smdp_sign.tag = 0x5F37;
    n_smdp_sign.value = second_byte;
    n_smdp_sign.length = 1;

    n_a0.tag = 0xA0;
    n_a0.pack.child = &n_87;
    n_87.tag = 0x87;
    n_87.value = third_byte;
    n_87.length = 1;

    n_a1.tag = 0xA1;
    n_a1.pack.child = &n_88;
    n_88.tag = 0x88;
    n_88.value = one_byte;
    n_88.length = 1;

    n_a3.tag = 0xA3;
    n_a3.pack.child = &n_86;
    n_86.tag = 0x86;
    n_86.value = second_byte;
    n_86.length = 1;

    n_smdp_sign.pack.next = &n_a0;
    n_a0.pack.next = &n_a1;
    n_a1.pack.next = &n_a3;

    if (euicc_derutil_pack_alloc(&reqbuf, &reqlen, &n_request) < 0) {
        goto err;
    }

    if (es10x_command(ctx, &respbuf, &resplen, reqbuf, reqlen) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&tmpnode, 0xBF37, respbuf, resplen) < 0) {
        goto err;
    }

    result->seqNumber = 1;
    result->iccid = NULL;
    result->bppCommandId = ES10B_BPP_COMMAND_ID_LOAD_PROFILE_ELEMENTS;
    result->errorReason = ES10B_ERROR_REASON_UNDEFINED;

    free(reqbuf);
    free(respbuf);
    return 0;

err:
    free(reqbuf);
    free(respbuf);
    return -1;
}

static cJSON *build_download_result_json(const struct es10b_load_bound_profile_package_result *result) {
    cJSON *jdata = cJSON_CreateObject();
    if (jdata == NULL) {
        // Memory allocation failed, return NULL to indicate error
        return NULL;
    }
    cJSON_AddNumberToObject(jdata, "seqNumber", (double)result->seqNumber);
    cJSON_AddStringOrNullToObject(jdata, "iccid", result->iccid);
    cJSON_AddStringToObject(jdata, "bppCommandId", euicc_bppcommandid2str(result->bppCommandId));
    cJSON_AddStringToObject(jdata, "errorReason", euicc_errorreason2str(result->errorReason));
    return jdata;
}

static cJSON *build_access_rules_json(const struct es8p_metadata_access_rule *rules) {
    cJSON *jrules = cJSON_CreateArray();
    const struct es8p_metadata_access_rule *rule = rules;

    if (!jrules) {
        return NULL;
    }

    while (rule) {
        cJSON *jrule = cJSON_CreateObject();
        if (!jrule) {
            cJSON_Delete(jrules);
            return NULL;
        }

        cJSON_AddStringOrNullToObject(jrule, "certificateHash", rule->certificateHash);
        cJSON_AddStringOrNullToObject(jrule, "packageName", rule->packageName);
        cJSON_AddItemToArray(jrules, jrule);

        rule = rule->next;
    }

    return jrules;
}

static int applet_main(int argc, char **argv) {
    int fret;
    const char *error_function_name = NULL;
    _cleanup_free_ char *error_detail = NULL;

    int opt;

    char *smdp = NULL;
    char *matchingId = NULL;
    char *imei = NULL;
    char *confirmation_code = NULL;
    char *activation_code = NULL;
    int interactive_preview = 0;

    _cleanup_(es10a_euicc_configured_addresses_free) struct es10a_euicc_configured_addresses configured_addresses = {0};
    struct es10b_load_bound_profile_package_result download_result = {0};

    cJSON *jmetadata = NULL;
    cJSON *jaccessRules = NULL;
    _cleanup_(es8p_metadata_free) struct es8p_metadata *profile_metadata = NULL;
    const bool is_simulated = getenv("LPAC_CUSTOM_ISD_R_AID") != NULL;

    while ((opt = getopt(argc, argv, opt_string)) != -1) {
        switch (opt) {
        case 's':
            smdp = strdup(optarg);
            break;
        case 'm':
            matchingId = strdup(optarg);
            break;
        case 'i':
            imei = strdup(optarg);
            break;
        case 'c':
            confirmation_code = strdup(optarg);
            break;
        case 'a':
            activation_code = strdup(optarg);
            if (strncasecmp(activation_code, "LPA:", 4) == 0)
                activation_code += 4; // ignore uri scheme
            break;
        case 'p':
            interactive_preview = 1;
            break;
        case 'h':
        case '?':
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("\t -s SM-DP+ Domain\n");
            printf("\t -m Matching ID\n");
            printf("\t -i IMEI\n");
            printf("\t -c Confirmation Code (Password)\n");
            printf("\t -a Activation Code (e.g: 'LPA:***')\n");
            printf("\t -p Interactive preview profile\n");
            printf("\t -h This help info\n");
            return -1;
        default:
            break;
        }
    }

    if (activation_code != NULL) {
        // SGP.22 v2.2.2; Page 111
        // Section: 4.1 (Activation Code)

        const char *token = NULL;
        int index = 0;

        while ((token = strsep(&activation_code, "$")) != NULL) {
            switch (index) {
            case 0: // Activation Code Format
                if (strncmp(token, "1", strlen(token)) != 0) {
                    error_function_name = "activation_code";
                    error_detail = strdup("invalid");
                    goto err;
                }
                break;
            case 1: // SM-DP+ Address
                smdp = strdup(token);
                break;
            case 2: // AC_Token or Matching ID
                matchingId = strdup(token);
                if (!is_strict_matching_id(matchingId)) {
                    error_function_name = "matching_id";
                    error_detail = strdup("invalid format, contains character not alphanumeric or dash");
                    goto err;
                }
                break;
            case 3: // SM-DP+ OID
                // ignored; this function is not implemented
                break;
            case 4: // Confirmation Code Required Flag
                if (strncmp(token, "1", strlen(token)) == 0 && confirmation_code == NULL) {
                    error_function_name = "confirmation_code";
                    error_detail = strdup("required");
                    goto err;
                }
                break;
            default:
                break;
            }
            index++;
        }
    }

    if (smdp == NULL) {
        jprint_progress("es10a_get_euicc_configured_addresses", NULL);
        if (es10a_get_euicc_configured_addresses(&euicc_ctx, &configured_addresses)) {
            error_function_name = "es10a_get_euicc_configured_addresses";
            error_detail = NULL;
            goto err;
        } else {
            smdp = configured_addresses.defaultDpAddress;
        }
    }

    if (!smdp || (strlen(smdp) == 0)) {
        error_function_name = "smdp";
        error_detail = strdup("empty");
        goto err;
    }

    signal(SIGINT, sigint_handler);

    euicc_ctx.http.server_address = smdp;

    CANCELPOINT();
    if (is_simulated) {
        jprint_progress("es10b_get_euicc_challenge_r", smdp);
        if (es10b_get_euicc_challenge_r(&euicc_ctx, &euicc_ctx.http._internal.b64_euicc_challenge)) {
            error_function_name = "es10b_get_euicc_challenge_r";
            error_detail = NULL;
            goto err;
        }
    } else {
        jprint_progress("es10b_get_euicc_challenge_and_info", smdp);
        if (es10b_get_euicc_challenge_and_info(&euicc_ctx)) {
            error_function_name = "es10b_get_euicc_challenge_and_info";
            error_detail = NULL;
            goto err;
        }
    }

    CANCELPOINT();
    if (is_simulated) {
        jprint_progress("placeholder_initiate_auth", smdp);
        if (placeholder_initiate_auth(&euicc_ctx)) {
            error_function_name = "placeholder_initiate_auth";
            error_detail = NULL;
            goto err;
        }
    } else {
        jprint_progress("es9p_initiate_authentication", smdp);
        if (es9p_initiate_authentication(&euicc_ctx)) {
            error_function_name = "es9p_initiate_authentication";
            error_detail = strdup(euicc_ctx.http.status.message);
            goto err;
        }
    }

    CANCELPOINT();
    jprint_progress("es10b_authenticate_server", smdp);
    if (es10b_authenticate_server(&euicc_ctx, matchingId, imei)) {
        error_function_name = "es10b_authenticate_server";
        error_detail = NULL;
        goto err;
    }

    CANCELPOINT();
    if (is_simulated) {
        jprint_progress("placeholder_authenticate_client", smdp);
        if (placeholder_authenticate_client(&euicc_ctx)) {
            error_function_name = "placeholder_authenticate_client";
            error_detail = NULL;
            goto err;
        }
    } else {
        jprint_progress("es9p_authenticate_client", smdp);
        if (es9p_authenticate_client(&euicc_ctx)) {
            error_function_name = "es9p_authenticate_client";
            error_detail = strdup(euicc_ctx.http.status.message);
            goto err;
        }
    }

    // preview here
    if (euicc_ctx.http._internal.prepare_download_param->b64_profileMetadata) {
        CANCELPOINT();
        if (es8p_metadata_parse(&profile_metadata,
                                euicc_ctx.http._internal.prepare_download_param->b64_profileMetadata)) {
            error_function_name = "es8p_metadata_parse";
            error_detail = NULL;
            goto err;
        }

        jmetadata = cJSON_CreateObject();

        cJSON_AddStringOrNullToObject(jmetadata, "iccid", profile_metadata->iccid);
        cJSON_AddStringOrNullToObject(jmetadata, "serviceProviderName", profile_metadata->serviceProviderName);
        cJSON_AddStringOrNullToObject(jmetadata, "profileName", profile_metadata->profileName);
        cJSON_AddStringOrNullToObject(jmetadata, "iconType", euicc_icontype2str(profile_metadata->iconType));
        cJSON_AddStringOrNullToObject(jmetadata, "icon", profile_metadata->icon);
        cJSON_AddStringOrNullToObject(jmetadata, "profileClass",
                                      euicc_profileclass2str(profile_metadata->profileClass));
        if (profile_metadata->accessRules) {
            jaccessRules = build_access_rules_json(profile_metadata->accessRules);
            if (jaccessRules) {
                cJSON_AddItemToObject(jmetadata, "accessRules", jaccessRules);
                jaccessRules = NULL;
            }
        }

        jprint_progress_obj("es8p_metadata_parse", jmetadata);

        if (interactive_preview) {
            int c;
            jprint_progress("preview", "y/n");
            c = getchar();
            if (c != 'y' && c != 'Y') {
                cancelled = 1;
            }
        }
    }

    CANCELPOINT();
    jprint_progress("es10b_prepare_download", smdp);
    if (es10b_prepare_download(&euicc_ctx, confirmation_code)) {
        error_function_name = "es10b_prepare_download";
        error_detail = NULL;
        goto err;
    }

    CANCELPOINT();
    if (is_simulated) {
        jprint_progress("send_placeholder_bpp", smdp);
        if (send_placeholder_bpp(&euicc_ctx, &download_result)) {
            error_function_name = "send_placeholder_bpp";
            error_detail = NULL;
            goto err;
        }
    } else {
        jprint_progress("es9p_get_bound_profile_package", smdp);
        if (es9p_get_bound_profile_package(&euicc_ctx)) {
            error_function_name = "es9p_get_bound_profile_package";
            error_detail = strdup(euicc_ctx.http.status.message);
            goto err;
        }

        CANCELPOINT();
        jprint_progress("es10b_load_bound_profile_package", smdp);
        if (es10b_load_bound_profile_package(&euicc_ctx, &download_result)) {
            jprint_progress_obj("es10b_load_bound_profile_package:result", build_download_result_json(&download_result));

            char buffer[256];

            snprintf(buffer, sizeof(buffer), "%s,%s", euicc_bppcommandid2str(download_result.bppCommandId),
                     euicc_errorreason2str(download_result.errorReason));
            error_function_name = "es10b_load_bound_profile_package";
            error_detail = strdup(buffer);

            goto err;
        }
    }

    jprint_success(build_download_result_json(&download_result));

    fret = 0;
    goto exit;

err:
    fret = -1;
    if (!is_simulated) {
        jprint_progress("es10b_cancel_session", smdp);
        es10b_cancel_session(&euicc_ctx, ES10B_CANCEL_SESSION_REASON_ENDUSERREJECTION);
        jprint_progress("es9p_cancel_session", smdp);
        es9p_cancel_session(&euicc_ctx);
    }
    if (!cancelled) {
        jprint_error(error_function_name, error_detail);
    } else {
        jprint_error("cancelled", NULL);
    }
exit:
    euicc_http_cleanup(&euicc_ctx);
    return fret;
}

struct applet_entry applet_profile_download = {
    .name = "download",
    .main = applet_main,
};
