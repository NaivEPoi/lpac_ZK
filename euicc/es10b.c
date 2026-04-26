#include "es10b.h"
#include "euicc.private.h"

#include "base64.h"
#include "derutil.h"
#include "hexutil.h"
#include "sha256.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int es10b_prepare_download_r(struct euicc_ctx *ctx, char **b64_PrepareDownloadResponse,
                             struct es10b_prepare_download_param *param,
                             struct es10b_prepare_download_param_user *param_user) {
    int fret = 0;
    uint8_t *reqbuf = NULL;
    uint32_t reqlen;
    uint8_t *respbuf = NULL;
    unsigned resplen;

    EUICC_SHA256_CTX sha256ctx;
    uint8_t hashCC[SHA256_BLOCK_SIZE];

    uint8_t *smdpSigned2 = NULL, *smdpSignature2 = NULL, *smdpCertificate = NULL;
    int smdpSigned2_len, smdpSignature2_len, smdpCertificate_len;
    struct euicc_derutil_node n_request, n_smdpSigned2, n_smdpSignature2, n_smdpCertificate, n_hashCc, n_transactionId,
        n_ccRequiredFlag;

    *b64_PrepareDownloadResponse = NULL;

    memset(&n_request, 0, sizeof(n_request));
    memset(&n_smdpSigned2, 0, sizeof(n_smdpSigned2));
    memset(&n_smdpSignature2, 0, sizeof(n_smdpSignature2));
    memset(&n_smdpCertificate, 0, sizeof(n_smdpCertificate));
    memset(&n_hashCc, 0, sizeof(n_hashCc));

    smdpSigned2 = malloc(euicc_base64_decode_len(param->b64_smdpSigned2));
    if (!smdpSigned2) {
        goto err;
    }

    smdpSignature2 = malloc(euicc_base64_decode_len(param->b64_smdpSignature2));
    if (!smdpSignature2) {
        goto err;
    }

    smdpCertificate = malloc(euicc_base64_decode_len(param->b64_smdpCertificate));
    if (!smdpCertificate) {
        goto err;
    }

    if ((smdpSigned2_len = euicc_base64_decode(smdpSigned2, param->b64_smdpSigned2)) < 0) {
        goto err;
    }

    if ((smdpSignature2_len = euicc_base64_decode(smdpSignature2, param->b64_smdpSignature2)) < 0) {
        goto err;
    }

    if ((smdpCertificate_len = euicc_base64_decode(smdpCertificate, param->b64_smdpCertificate)) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&n_smdpSigned2, 0x30, smdpSigned2, smdpSigned2_len) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&n_smdpSignature2, 0x5F37, smdpSignature2, smdpSignature2_len) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&n_smdpCertificate, 0x30, smdpCertificate, smdpCertificate_len) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&n_transactionId, 0x80, n_smdpSigned2.value, n_smdpSigned2.length) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&n_ccRequiredFlag, 0x01, n_smdpSigned2.value, n_smdpSigned2.length) < 0) {
        goto err;
    }

    n_request.tag = 0xBF21;
    n_request.pack.child = &n_smdpSigned2;
    n_smdpSigned2.pack.next = &n_smdpSignature2;

    if (euicc_derutil_convert_bin2long(n_ccRequiredFlag.value, n_ccRequiredFlag.length)) {
        if ((!param_user->confirmationCode) || (strlen(param_user->confirmationCode) == 0)) {
            goto err;
        }

        memset(&sha256ctx, 0, sizeof(sha256ctx));
        euicc_sha256_init(&sha256ctx);
        euicc_sha256_update(&sha256ctx, (const uint8_t *)param_user->confirmationCode,
                            strlen(param_user->confirmationCode));
        euicc_sha256_final(&sha256ctx, hashCC);

        memset(&sha256ctx, 0, sizeof(sha256ctx));
        euicc_sha256_init(&sha256ctx);
        euicc_sha256_update(&sha256ctx, hashCC, sizeof(hashCC));
        euicc_sha256_update(&sha256ctx, n_transactionId.value, n_transactionId.length);
        euicc_sha256_final(&sha256ctx, hashCC);

        n_hashCc.tag = 0x04;
        n_hashCc.value = hashCC;
        n_hashCc.length = sizeof(hashCC);

        n_smdpSignature2.pack.next = &n_hashCc;
        n_hashCc.pack.next = &n_smdpCertificate;
    } else {
        n_smdpSignature2.pack.next = &n_smdpCertificate;
    }

    if (euicc_derutil_pack_alloc(&reqbuf, &reqlen, &n_request) < 0) {
        goto err;
    }

    free(smdpSigned2);
    smdpSigned2 = NULL;
    free(smdpSignature2);
    smdpSignature2 = NULL;
    free(smdpCertificate);
    smdpCertificate = NULL;

    if (es10x_command(ctx, &respbuf, &resplen, reqbuf, reqlen) < 0) {
        goto err;
    }

    free(reqbuf);
    reqbuf = NULL;

    *b64_PrepareDownloadResponse = malloc(euicc_base64_encode_len(resplen));
    if (!(*b64_PrepareDownloadResponse)) {
        goto err;
    }

    if (euicc_base64_encode(*b64_PrepareDownloadResponse, respbuf, resplen) < 0) {
        goto err;
    }

    fret = 0;

    goto exit;

err:
    fret = -1;
    free(*b64_PrepareDownloadResponse);
    *b64_PrepareDownloadResponse = NULL;
exit:
    free(smdpSigned2);
    smdpSigned2 = NULL;
    free(smdpSignature2);
    smdpSignature2 = NULL;
    free(smdpCertificate);
    smdpCertificate = NULL;
    free(reqbuf);
    reqbuf = NULL;
    free(respbuf);
    respbuf = NULL;
    return fret;
}

int es10b_zk_profile_request(struct euicc_ctx *ctx, const char *b64_mno_challenge,
                             char **b64_zk_profile_response) {
    int fret = 0;
    uint8_t *challenge = NULL;
    int challenge_len;
    uint8_t *reqbuf = NULL;
    uint32_t reqlen;
    uint8_t *respbuf = NULL;
    unsigned resplen;
    struct euicc_derutil_node n_request, n_challenge;

    *b64_zk_profile_response = NULL;
    memset(&n_request, 0, sizeof(n_request));
    memset(&n_challenge, 0, sizeof(n_challenge));

    challenge = malloc(euicc_base64_decode_len(b64_mno_challenge));
    if (!challenge) {
        goto err;
    }
    challenge_len = euicc_base64_decode(challenge, b64_mno_challenge);
    if (challenge_len != 16) {
        goto err;
    }

    n_request.tag = 0xBF42;
    n_request.pack.child = &n_challenge;
    n_challenge.tag = 0x80;
    n_challenge.value = challenge;
    n_challenge.length = (uint32_t)challenge_len;

    if (euicc_derutil_pack_alloc(&reqbuf, &reqlen, &n_request) < 0) {
        goto err;
    }
    if (es10x_command(ctx, &respbuf, &resplen, reqbuf, reqlen) < 0) {
        goto err;
    }

    *b64_zk_profile_response = malloc(euicc_base64_encode_len(resplen));
    if (!*b64_zk_profile_response) {
        goto err;
    }
    if (euicc_base64_encode(*b64_zk_profile_response, respbuf, resplen) < 0) {
        goto err;
    }

    goto exit;

err:
    fret = -1;
    free(*b64_zk_profile_response);
    *b64_zk_profile_response = NULL;
exit:
    free(challenge);
    free(reqbuf);
    free(respbuf);
    return fret;
}

int es10b_set_eligibility_data(struct euicc_ctx *ctx, const uint8_t *set_eligibility_req_der,
                               uint32_t der_len, int *result_code) {
    int fret = 0;
    uint8_t *respbuf = NULL;
    unsigned resplen;
    struct euicc_derutil_node n_bf43, n_choice;

    *result_code = -1;
    if (es10x_command(ctx, &respbuf, &resplen, set_eligibility_req_der, der_len) < 0) {
        goto err;
    }
    if (euicc_derutil_unpack_find_tag(&n_bf43, 0xBF43, respbuf, resplen) < 0) {
        goto err;
    }
    if (euicc_derutil_unpack_first(&n_choice, n_bf43.value, n_bf43.length) < 0) {
        goto err;
    }
    if (n_choice.tag == 0xA0) {
        *result_code = 0;
        goto exit;
    }
    if (n_choice.tag == 0xA1) {
        struct euicc_derutil_node n_error;
        if (euicc_derutil_unpack_find_tag(&n_error, 0x02, n_choice.value, n_choice.length) == 0) {
            *result_code = (int)euicc_derutil_convert_bin2long(n_error.value, n_error.length);
        }
        goto err;
    }
    goto err;

err:
    fret = -1;
exit:
    free(respbuf);
    return fret;
}

static int es10b_load_bound_profile_package_tx(struct euicc_ctx *ctx,
                                               struct es10b_load_bound_profile_package_result *result,
                                               const uint8_t *reqbuf, int reqbuf_len) {
    int fret = 0;
    uint8_t *respbuf = NULL;
    unsigned resplen;

    result->seqNumber = 0;
    result->bppCommandId = ES10B_BPP_COMMAND_ID_UNDEFINED;
    result->errorReason = ES10B_ERROR_REASON_UNDEFINED;
    result->iccid = NULL;

    if (es10x_command(ctx, &respbuf, &resplen, reqbuf, reqbuf_len) < 0) {
        goto err;
    }

    if (resplen > 0) {
        struct euicc_derutil_node tmpnode, n_notificationMetadata, n_sequenceNumber, n_iccid, n_finalResult;

        if (euicc_derutil_unpack_find_tag(&tmpnode, 0xBF37, respbuf, resplen) < 0) // ProfileInstallationResult
        {
            goto err;
        }

        if (euicc_derutil_unpack_find_tag(&tmpnode, 0xBF27, tmpnode.value, tmpnode.length)
            < 0) // ProfileInstallationResultData
        {
            goto err;
        }

        if (euicc_derutil_unpack_find_tag(&n_notificationMetadata, 0xBF2F, tmpnode.value,
                                          tmpnode.length)
            < 0) // NotificationMetadata
        {
            goto err;
        }

        if (euicc_derutil_unpack_find_tag(&tmpnode, 0xA2, tmpnode.value, tmpnode.length) < 0) // finalResult
        {
            goto err;
        }

        if (euicc_derutil_unpack_first(&n_finalResult, tmpnode.value, tmpnode.length) < 0) {
            goto err;
        }

        if (euicc_derutil_unpack_find_tag(&n_sequenceNumber, 0x80, n_notificationMetadata.value,
                                          n_notificationMetadata.length)
            == 0) {
            result->seqNumber = euicc_derutil_convert_bin2long(n_sequenceNumber.value, n_sequenceNumber.length);
        }

        if (euicc_derutil_unpack_find_tag(&n_iccid, 0x5A, n_notificationMetadata.value, n_notificationMetadata.length)
            == 0) {
            result->iccid = malloc((n_iccid.length * 2) + 1);
            if (result->iccid) {
                if (euicc_hexutil_bin2gsmbcd(result->iccid, (n_iccid.length * 2) + 1, n_iccid.value, n_iccid.length)
                    < 0) {
                    free(result->iccid);
                    result->iccid = NULL;
                }
            }
        }

        switch (n_finalResult.tag) {
        case 0xA0: // SuccessResult
            break;
        case 0xA1: // ErrorResult
            tmpnode.self.ptr = n_finalResult.value;
            tmpnode.self.length = 0;
            while (euicc_derutil_unpack_next(&tmpnode, &tmpnode, n_finalResult.value, n_finalResult.length) == 0) {
                long tmpint;
                switch (tmpnode.tag) {
                case 0x80:
                    tmpint = euicc_derutil_convert_bin2long(tmpnode.value, tmpnode.length);
                    switch (tmpint) {
                    case ES10B_BPP_COMMAND_ID_INITIALISE_SECURE_CHANNEL:
                    case ES10B_BPP_COMMAND_ID_CONFIGURE_ISDP:
                    case ES10B_BPP_COMMAND_ID_STORE_METADATA:
                    case ES10B_BPP_COMMAND_ID_STORE_METADATA2:
                    case ES10B_BPP_COMMAND_ID_REPLACE_SESSION_KEYS:
                    case ES10B_BPP_COMMAND_ID_LOAD_PROFILE_ELEMENTS:
                        result->bppCommandId = tmpint;
                        break;
                    default:
                        result->bppCommandId = ES10B_BPP_COMMAND_ID_UNDEFINED;
                        break;
                    }
                    break;
                case 0x81:
                    tmpint = euicc_derutil_convert_bin2long(tmpnode.value, tmpnode.length);
                    switch (tmpint) {
                    case ES10B_ERROR_REASON_INCORRECT_INPUT_VALUES:
                    case ES10B_ERROR_REASON_INVALID_SIGNATURE:
                    case ES10B_ERROR_REASON_INVALID_TRANSACTION_ID:
                    case ES10B_ERROR_REASON_UNSUPPORTED_CRT_VALUES:
                    case ES10B_ERROR_REASON_UNSUPPORTED_REMOTE_OPERATION_TYPE:
                    case ES10B_ERROR_REASON_UNSUPPORTED_PROFILE_CLASS:
                    case ES10B_ERROR_REASON_SCP03T_STRUCTURE_ERROR:
                    case ES10B_ERROR_REASON_SCP03T_SECURITY_ERROR:
                    case ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_ICCID_ALREADY_EXISTS_ON_EUICC:
                    case ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_INSUFFICIENT_MEMORY_FOR_PROFILE:
                    case ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_INTERRUPTION:
                    case ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_PE_PROCESSING_ERROR:
                    case ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_DATA_MISMATCH:
                    case ES10B_ERROR_REASON_TEST_PROFILE_INSTALL_FAILED_DUE_TO_INVALID_NAA_KEY:
                    case ES10B_ERROR_REASON_PPR_NOT_ALLOWED:
                    case ES10B_ERROR_REASON_INSTALL_FAILED_DUE_TO_UNKNOWN_ERROR:
                        result->errorReason = tmpint;
                        break;
                    default:
                        result->errorReason = ES10B_ERROR_REASON_UNDEFINED;
                        break;
                    }
                    break;
                default:
                    break;
                }
            }
            goto err;
        default:
            goto err;
        }
    }

    fret = 0;
    goto exit;

err:
    fret = -1;
exit:
    free(respbuf);
    respbuf = NULL;
    return fret;
}

int es10b_load_bound_profile_package_r(struct euicc_ctx *ctx, struct es10b_load_bound_profile_package_result *result,
                                       const char *b64_BoundProfilePackage) {
    int fret = 0;

    uint8_t *bpp = NULL;
    int bpp_len;

    const uint8_t *reqbuf;
    int reqbuf_len;

    struct euicc_derutil_node tmpnode, tmpchildnode, n_BoundProfilePackage;

    bpp = malloc(euicc_base64_decode_len(b64_BoundProfilePackage));
    if (!bpp) {
        goto err;
    }
    if ((bpp_len = euicc_base64_decode(bpp, b64_BoundProfilePackage)) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&n_BoundProfilePackage, 0xBF36, bpp, bpp_len) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&tmpnode, 0xBF23, n_BoundProfilePackage.value, n_BoundProfilePackage.length)
        < 0) {
        goto err;
    }

    reqbuf = n_BoundProfilePackage.self.ptr;
    reqbuf_len = tmpnode.self.ptr - n_BoundProfilePackage.self.ptr + tmpnode.self.length;

    if (es10b_load_bound_profile_package_tx(ctx, result, reqbuf, reqbuf_len) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&tmpnode, 0xA0, n_BoundProfilePackage.value, n_BoundProfilePackage.length) < 0) {
        goto err;
    }

    reqbuf = tmpnode.self.ptr;
    reqbuf_len = tmpnode.self.length;

    if (es10b_load_bound_profile_package_tx(ctx, result, reqbuf, reqbuf_len) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&tmpnode, 0xA1, n_BoundProfilePackage.value, n_BoundProfilePackage.length) < 0) {
        goto err;
    }

    reqbuf = tmpnode.self.ptr;
    reqbuf_len = tmpnode.value - tmpnode.self.ptr;

    if (es10b_load_bound_profile_package_tx(ctx, result, reqbuf, reqbuf_len) < 0) {
        goto err;
    }

    tmpchildnode.self.ptr = tmpnode.value;
    tmpchildnode.self.length = 0;

    while (euicc_derutil_unpack_next(&tmpchildnode, &tmpchildnode, tmpnode.value, tmpnode.length) == 0) {
        reqbuf = tmpchildnode.self.ptr;
        reqbuf_len = tmpchildnode.self.length;

        if (es10b_load_bound_profile_package_tx(ctx, result, reqbuf, reqbuf_len) < 0) {
            goto err;
        }
    }

    if (euicc_derutil_unpack_find_tag(&tmpnode, 0xA2, n_BoundProfilePackage.value, n_BoundProfilePackage.length) == 0) {
        reqbuf = tmpnode.self.ptr;
        reqbuf_len = tmpnode.self.length;

        if (es10b_load_bound_profile_package_tx(ctx, result, reqbuf, reqbuf_len) < 0) {
            goto err;
        }
    }

    if (euicc_derutil_unpack_find_tag(&tmpnode, 0xA3, n_BoundProfilePackage.value, n_BoundProfilePackage.length) < 0) {
        goto err;
    }

    reqbuf = tmpnode.self.ptr;
    reqbuf_len = tmpnode.value - tmpnode.self.ptr;

    if (es10b_load_bound_profile_package_tx(ctx, result, reqbuf, reqbuf_len) < 0) {
        goto err;
    }

    tmpchildnode.self.ptr = tmpnode.value;
    tmpchildnode.self.length = 0;

    while (euicc_derutil_unpack_next(&tmpchildnode, &tmpchildnode, tmpnode.value, tmpnode.length) == 0) {
        reqbuf = tmpchildnode.self.ptr;
        reqbuf_len = tmpchildnode.self.length;

        if (es10b_load_bound_profile_package_tx(ctx, result, reqbuf, reqbuf_len) < 0) {
            goto err;
        }
    }

    goto exit;

err:
    fret = -1;
exit:
    free(bpp);
    bpp = NULL;
    return fret;
}

int es10b_get_euicc_challenge_r(struct euicc_ctx *ctx, char **b64_euiccChallenge) {
    int fret = 0;
    struct euicc_derutil_node n_request = {
        .tag = 0xBF2E, // GetEuiccDataRequest
    };
    uint32_t reqlen;
    uint8_t *respbuf = NULL;
    unsigned resplen;

    struct euicc_derutil_node tmpnode;

    reqlen = sizeof(ctx->apdu._internal.request_buffer.body);
    if (euicc_derutil_pack(ctx->apdu._internal.request_buffer.body, &reqlen, &n_request)) {
        goto err;
    }

    if (es10x_command(ctx, &respbuf, &resplen, ctx->apdu._internal.request_buffer.body, reqlen) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&tmpnode, n_request.tag, respbuf, resplen)) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&tmpnode, 0x80, tmpnode.value, tmpnode.length)) {
        goto err;
    }

    *b64_euiccChallenge = malloc(euicc_base64_encode_len(tmpnode.length));
    if (!(*b64_euiccChallenge)) {
        goto err;
    }
    if (euicc_base64_encode(*b64_euiccChallenge, tmpnode.value, tmpnode.length) < 0) {
        goto err;
    }

    goto exit;

err:
    fret = -1;
    free(*b64_euiccChallenge);
    *b64_euiccChallenge = NULL;
exit:
    free(respbuf);
    respbuf = NULL;
    return fret;
}

int es10b_get_euicc_info_r(struct euicc_ctx *ctx, char **b64_EUICCInfo1) {
    int fret = 0;
    struct euicc_derutil_node n_request = {
        .tag = 0xBF20, // GetEuiccInfo1Request
    };
    uint32_t reqlen;
    uint8_t *respbuf = NULL;
    unsigned resplen;

    struct euicc_derutil_node tmpnode;

    reqlen = sizeof(ctx->apdu._internal.request_buffer.body);
    if (euicc_derutil_pack(ctx->apdu._internal.request_buffer.body, &reqlen, &n_request)) {
        goto err;
    }

    if (es10x_command(ctx, &respbuf, &resplen, ctx->apdu._internal.request_buffer.body, reqlen) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&tmpnode, n_request.tag, respbuf, resplen)) {
        goto err;
    }

    *b64_EUICCInfo1 = malloc(euicc_base64_encode_len(tmpnode.self.length));
    if (!(*b64_EUICCInfo1)) {
        goto err;
    }
    if (euicc_base64_encode(*b64_EUICCInfo1, tmpnode.self.ptr, tmpnode.self.length) < 0) {
        goto err;
    }

    goto exit;

err:
    fret = -1;
    free(*b64_EUICCInfo1);
    *b64_EUICCInfo1 = NULL;
exit:
    free(respbuf);
    respbuf = NULL;
    return fret;
}

int es10b_authenticate_server_r(struct euicc_ctx *ctx, uint8_t **transaction_id, uint32_t *transaction_id_len,
                                char **b64_AuthenticateServerResponse, struct es10b_authenticate_server_param *param,
                                struct es10b_authenticate_server_param_user *param_user) {
    int fret = 0;
    uint8_t *reqbuf = NULL;
    uint32_t reqlen;
    uint8_t *respbuf = NULL;
    unsigned resplen;

    uint8_t imei[8];
    uint8_t *serverSigned1 = NULL, *serverSignature1 = NULL, *euiccCiPKIdToBeUsed = NULL, *serverCertificate = NULL;
    int serverSigned1_len, serverSignature1_len, euiccCiPKIdToBeUsed_len, serverCertificate_len;
    struct euicc_derutil_node n_request, n_serverSigned1, n_transactionId, n_serverSignature1, n_euiccCiPKIdToBeUsed,
        n_serverCertificate, n_CtxParams1, n_matchingId, n_deviceInfo, n_tac, n_deviceCapabilities, n_imei;

    *transaction_id = NULL;
    *transaction_id_len = 0;
    *b64_AuthenticateServerResponse = NULL;

    memset(&n_request, 0, sizeof(n_request));
    memset(&n_serverSigned1, 0, sizeof(n_serverSigned1));
    memset(&n_serverSignature1, 0, sizeof(n_serverSignature1));
    memset(&n_euiccCiPKIdToBeUsed, 0, sizeof(n_euiccCiPKIdToBeUsed));
    memset(&n_serverCertificate, 0, sizeof(n_serverCertificate));
    memset(&n_CtxParams1, 0, sizeof(n_CtxParams1));
    memset(&n_matchingId, 0, sizeof(n_matchingId));
    memset(&n_deviceInfo, 0, sizeof(n_deviceInfo));
    memset(&n_tac, 0, sizeof(n_tac));
    memset(&n_deviceCapabilities, 0, sizeof(n_deviceCapabilities));
    memset(&n_imei, 0, sizeof(n_imei));

    serverSigned1 = malloc(euicc_base64_decode_len(param->b64_serverSigned1));
    if (!serverSigned1) {
        goto err;
    }

    serverSignature1 = malloc(euicc_base64_decode_len(param->b64_serverSignature1));
    if (!serverSignature1) {
        goto err;
    }

    euiccCiPKIdToBeUsed = malloc(euicc_base64_decode_len(param->b64_euiccCiPKIdToBeUsed));
    if (!euiccCiPKIdToBeUsed) {
        goto err;
    }

    serverCertificate = malloc(euicc_base64_decode_len(param->b64_serverCertificate));
    if (!serverCertificate) {
        goto err;
    }

    if ((serverSigned1_len = euicc_base64_decode(serverSigned1, param->b64_serverSigned1)) < 0) {
        goto err;
    }

    if ((serverSignature1_len = euicc_base64_decode(serverSignature1, param->b64_serverSignature1)) < 0) {
        goto err;
    }

    if ((euiccCiPKIdToBeUsed_len = euicc_base64_decode(euiccCiPKIdToBeUsed, param->b64_euiccCiPKIdToBeUsed)) < 0) {
        goto err;
    }

    if ((serverCertificate_len = euicc_base64_decode(serverCertificate, param->b64_serverCertificate)) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&n_serverSigned1, 0x30, serverSigned1, serverSigned1_len) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&n_transactionId, 0x80, n_serverSigned1.value, n_serverSigned1.length) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&n_serverSignature1, 0x5F37, serverSignature1, serverSignature1_len) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&n_euiccCiPKIdToBeUsed, 0x04, euiccCiPKIdToBeUsed, euiccCiPKIdToBeUsed_len) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&n_serverCertificate, 0x30, serverCertificate, serverCertificate_len) < 0) {
        goto err;
    }

    *transaction_id_len = n_transactionId.length;
    *transaction_id = malloc(n_transactionId.length);
    if (!(*transaction_id)) {
        goto err;
    }
    memcpy(*transaction_id, n_transactionId.value, n_transactionId.length);

    n_request.tag = 0xBF38;
    n_request.pack.child = &n_serverSigned1;
    n_serverSigned1.pack.next = &n_serverSignature1;
    n_serverSignature1.pack.next = &n_euiccCiPKIdToBeUsed;
    n_euiccCiPKIdToBeUsed.pack.next = &n_serverCertificate;
    n_serverCertificate.pack.next = &n_CtxParams1;
    n_CtxParams1.tag = 0xA0;

    n_deviceInfo.tag = 0xA1;
    n_deviceInfo.pack.child = &n_tac;
    n_tac.tag = 0x80;
    n_tac.value = imei;
    n_tac.length = 4;
    n_tac.pack.next = &n_deviceCapabilities;
    n_deviceCapabilities.tag = 0xA1;
    if (param_user->imei) {
        int imei_len;

        imei_len = euicc_hexutil_gsmbcd2bin(imei, sizeof(imei), param_user->imei, 0);
        if (imei_len < 0) {
            goto err;
        }

        n_deviceCapabilities.pack.next = &n_imei;
        n_imei.tag = 0x82;
        n_imei.value = imei;
        n_imei.length = imei_len;
    } else {
        memcpy(imei, (uint8_t[]){0x35, 0x29, 0x06, 0x11}, 4);
    }

    if (param_user->matchingId) {
        n_CtxParams1.pack.child = &n_matchingId;
        n_matchingId.tag = 0x80;
        n_matchingId.value = (const uint8_t *)param_user->matchingId;
        n_matchingId.length = strlen(param_user->matchingId);
        n_matchingId.pack.next = &n_deviceInfo;
    } else {
        n_CtxParams1.pack.child = &n_deviceInfo;
    }

    if (euicc_derutil_pack_alloc(&reqbuf, &reqlen, &n_request) < 0) {
        goto err;
    }

    free(serverSigned1);
    serverSigned1 = NULL;
    free(serverSignature1);
    serverSignature1 = NULL;
    free(euiccCiPKIdToBeUsed);
    euiccCiPKIdToBeUsed = NULL;
    free(serverCertificate);
    serverCertificate = NULL;

    if (es10x_command(ctx, &respbuf, &resplen, reqbuf, reqlen) < 0) {
        goto err;
    }

    free(reqbuf);
    reqbuf = NULL;

    *b64_AuthenticateServerResponse = malloc(euicc_base64_encode_len(resplen));
    if (!(*b64_AuthenticateServerResponse)) {
        goto err;
    }

    if (euicc_base64_encode(*b64_AuthenticateServerResponse, respbuf, resplen) < 0) {
        goto err;
    }

    fret = 0;

    goto exit;

err:
    fret = -1;
    free(*transaction_id);
    *transaction_id = NULL;
    *transaction_id_len = 0;
    free(*b64_AuthenticateServerResponse);
    *b64_AuthenticateServerResponse = NULL;
exit:
    free(serverSigned1);
    serverSigned1 = NULL;
    free(serverSignature1);
    serverSignature1 = NULL;
    free(euiccCiPKIdToBeUsed);
    euiccCiPKIdToBeUsed = NULL;
    free(serverCertificate);
    serverCertificate = NULL;
    free(reqbuf);
    reqbuf = NULL;
    free(respbuf);
    respbuf = NULL;
    return fret;
}

int es10b_cancel_session_r(struct euicc_ctx *ctx, char **b64_CancelSessionResponse,
                           struct es10b_cancel_session_param *param) {
    int fret = 0;
    struct euicc_derutil_node n_request, n_transactionId, n_reason;
    uint8_t reason_buf[sizeof(enum es10b_cancel_session_reason)];
    uint32_t reason_buf_len = sizeof(reason_buf);
    uint32_t reqlen;
    uint8_t *respbuf = NULL;
    unsigned resplen;

    struct euicc_derutil_node tmpnode;

    if (euicc_derutil_convert_long2bin(reason_buf, &reason_buf_len, param->reason) < 0) {
        goto err;
    }

    memset(&n_request, 0, sizeof(n_request));
    memset(&n_transactionId, 0, sizeof(n_transactionId));
    memset(&n_reason, 0, sizeof(n_reason));

    n_request.tag = 0xBF41; // CancelSessionRequest
    n_request.pack.child = &n_transactionId;

    n_transactionId.tag = 0x80;
    n_transactionId.value = (const uint8_t *)param->transactionId;
    n_transactionId.length = param->transactionIdLen;
    n_transactionId.pack.next = &n_reason;

    n_reason.tag = 0x81;
    n_reason.value = reason_buf;
    n_reason.length = reason_buf_len;

    reqlen = sizeof(ctx->apdu._internal.request_buffer.body);
    if (euicc_derutil_pack(ctx->apdu._internal.request_buffer.body, &reqlen, &n_request)) {
        goto err;
    }

    if (es10x_command(ctx, &respbuf, &resplen, ctx->apdu._internal.request_buffer.body, reqlen) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&tmpnode, n_request.tag, respbuf, resplen)) {
        goto err;
    }

    *b64_CancelSessionResponse = malloc(euicc_base64_encode_len(tmpnode.self.length));
    if (!(*b64_CancelSessionResponse)) {
        goto err;
    }
    if (euicc_base64_encode(*b64_CancelSessionResponse, tmpnode.self.ptr, tmpnode.self.length) < 0) {
        goto err;
    }

    goto exit;

err:
    fret = -1;
    free(*b64_CancelSessionResponse);
    *b64_CancelSessionResponse = NULL;
exit:
    free(respbuf);
    respbuf = NULL;
    return fret;
}

void es10b_prepare_download_param_free(struct es10b_prepare_download_param *param) {
    if (!param) {
        return;
    }

    free(param->b64_profileMetadata);
    free(param->b64_smdpCertificate);
    free(param->b64_smdpSignature2);
    free(param->b64_smdpSigned2);

    memset(param, 0x00, sizeof(*param));
}

void es10b_authenticate_server_param_free(struct es10b_authenticate_server_param *param) {
    if (!param) {
        return;
    }

    free(param->b64_euiccCiPKIdToBeUsed);
    free(param->b64_serverCertificate);
    free(param->b64_serverSignature1);
    free(param->b64_serverSigned1);

    memset(param, 0x00, sizeof(*param));
}

int es10b_prepare_download(struct euicc_ctx *ctx, const char *confirmationCode) {
    int fret;

    struct es10b_prepare_download_param_user param_user = {
        .confirmationCode = confirmationCode,
    };

    if (ctx->http._internal.b64_prepare_download_response) {
        return -1;
    }

    if (ctx->http._internal.prepare_download_param == NULL) {
        return -1;
    }

    fret = es10b_prepare_download_r(ctx, &ctx->http._internal.b64_prepare_download_response,
                                    ctx->http._internal.prepare_download_param, &param_user);
    if (fret < 0) {
        ctx->http._internal.b64_prepare_download_response = NULL;
        return fret;
    }

    es10b_prepare_download_param_free(ctx->http._internal.prepare_download_param);
    free(ctx->http._internal.prepare_download_param);
    ctx->http._internal.prepare_download_param = NULL;

    return fret;
}

int es10b_load_bound_profile_package(struct euicc_ctx *ctx, struct es10b_load_bound_profile_package_result *result) {
    int fret;

    if (ctx->http._internal.b64_bound_profile_package == NULL) {
        return -1;
    }

    fret = es10b_load_bound_profile_package_r(ctx, result, ctx->http._internal.b64_bound_profile_package);
    if (fret < 0) {
        return fret;
    }

    free(ctx->http._internal.b64_bound_profile_package);
    ctx->http._internal.b64_bound_profile_package = NULL;

    return fret;
}

int es10b_get_euicc_challenge_and_info(struct euicc_ctx *ctx) {
    int fret;

    if (ctx->http._internal.b64_euicc_challenge) {
        return -1;
    }

    if (ctx->http._internal.b64_euicc_info_1) {
        return -1;
    }

    fret = es10b_get_euicc_challenge_r(ctx, &ctx->http._internal.b64_euicc_challenge);
    if (fret < 0) {
        goto err;
    }

    fret = es10b_get_euicc_info_r(ctx, &ctx->http._internal.b64_euicc_info_1);
    if (fret < 0) {
        goto err;
    }

    return fret;

err:
    free(ctx->http._internal.b64_euicc_challenge);
    ctx->http._internal.b64_euicc_challenge = NULL;
    free(ctx->http._internal.b64_euicc_info_1);
    ctx->http._internal.b64_euicc_info_1 = NULL;

    return -1;
}

int es10b_authenticate_server(struct euicc_ctx *ctx, const char *matchingId, const char *imei) {
    int fret;

    struct es10b_authenticate_server_param_user param_user = {
        .matchingId = matchingId,
        .imei = imei,
    };

    if (ctx->http._internal.b64_authenticate_server_response) {
        return -1;
    }

    if (ctx->http._internal.authenticate_server_param == NULL) {
        return -1;
    }

    fret = es10b_authenticate_server_r(ctx, &ctx->http._internal.transaction_id_bin,
                                       &ctx->http._internal.transaction_id_bin_len,
                                       &ctx->http._internal.b64_authenticate_server_response,
                                       ctx->http._internal.authenticate_server_param, &param_user);
    if (fret < 0) {
        ctx->http._internal.b64_authenticate_server_response = NULL;
        return fret;
    }

    es10b_authenticate_server_param_free(ctx->http._internal.authenticate_server_param);
    free(ctx->http._internal.authenticate_server_param);
    ctx->http._internal.authenticate_server_param = NULL;

    return fret;
}

int es10b_cancel_session(struct euicc_ctx *ctx, enum es10b_cancel_session_reason reason) {
    int fret;

    struct es10b_cancel_session_param param = {
        .transactionId = ctx->http._internal.transaction_id_bin,
        .transactionIdLen = ctx->http._internal.transaction_id_bin_len,
        .reason = reason,
    };

    if (ctx->http._internal.transaction_id_bin == NULL) {
        return -1;
    }

    if (ctx->http._internal.transaction_id_bin_len == 0) {
        return -1;
    }

    if (ctx->http._internal.b64_cancel_session_response) {
        return -1;
    }

    fret = es10b_cancel_session_r(ctx, &ctx->http._internal.b64_cancel_session_response, &param);

    if (fret < 0) {
        ctx->http._internal.b64_cancel_session_response = NULL;
    }

    return fret;
}

int es10b_list_notification(struct euicc_ctx *ctx, struct es10b_notification_metadata_list **notificationMetadataList) {
    int fret = 0;
    struct euicc_derutil_node n_request = {
        .tag = 0xBF28, // ListNotificationRequest
    };
    uint32_t reqlen;
    uint8_t *respbuf = NULL;
    unsigned resplen;

    struct euicc_derutil_node tmpnode, n_notificationMetadataList, n_NotificationMetadata;

    struct es10b_notification_metadata_list *list_wptr = NULL;

    *notificationMetadataList = NULL;

    reqlen = sizeof(ctx->apdu._internal.request_buffer.body);
    if (euicc_derutil_pack(ctx->apdu._internal.request_buffer.body, &reqlen, &n_request)) {
        goto err;
    }

    if (es10x_command(ctx, &respbuf, &resplen, ctx->apdu._internal.request_buffer.body, reqlen) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&tmpnode, n_request.tag, respbuf, resplen) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&n_notificationMetadataList, 0xA0, tmpnode.value, tmpnode.length) < 0) {
        goto err;
    }

    n_NotificationMetadata.self.ptr = n_notificationMetadataList.value;
    n_NotificationMetadata.self.length = 0;

    while (euicc_derutil_unpack_next(&n_NotificationMetadata, &n_NotificationMetadata, n_notificationMetadataList.value,
                                     n_notificationMetadataList.length)
           == 0) {
        struct es10b_notification_metadata_list *p;

        if (n_NotificationMetadata.tag != 0xBF2F) {
            continue;
        }

        p = malloc(sizeof(struct es10b_notification_metadata_list));
        if (!p) {
            goto err;
        }

        memset(p, 0, sizeof(*p));

        tmpnode.self.ptr = n_NotificationMetadata.value;
        tmpnode.self.length = 0;
        p->profileManagementOperation = ES10B_PROFILE_MANAGEMENT_OPERATION_NULL;
        while (
            euicc_derutil_unpack_next(&tmpnode, &tmpnode, n_NotificationMetadata.value, n_NotificationMetadata.length)
            == 0) {
            switch (tmpnode.tag) {
            case 0x80:
                p->seqNumber = euicc_derutil_convert_bin2long(tmpnode.value, tmpnode.length);
                break;
            case 0x81:
                if (tmpnode.length >= 2) {
                    switch (tmpnode.value[1]) {
                    case ES10B_PROFILE_MANAGEMENT_OPERATION_INSTALL:
                    case ES10B_PROFILE_MANAGEMENT_OPERATION_ENABLE:
                    case ES10B_PROFILE_MANAGEMENT_OPERATION_DISABLE:
                    case ES10B_PROFILE_MANAGEMENT_OPERATION_DELETE:
                        p->profileManagementOperation = tmpnode.value[1];
                        break;
                    default:
                        p->profileManagementOperation = ES10B_PROFILE_MANAGEMENT_OPERATION_UNDEFINED;
                        break;
                    }
                }
                break;
            case 0x0C:
                p->notificationAddress = malloc(tmpnode.length + 1);
                if (p->notificationAddress) {
                    memcpy(p->notificationAddress, tmpnode.value, tmpnode.length);
                    p->notificationAddress[tmpnode.length] = '\0';
                }
                break;
            case 0x5A:
                p->iccid = malloc((tmpnode.length * 2) + 1);
                if (p->iccid) {
                    if (euicc_hexutil_bin2gsmbcd(p->iccid, (tmpnode.length * 2) + 1, tmpnode.value, tmpnode.length)
                        < 0) {
                        free(p->iccid);
                        p->iccid = NULL;
                    }
                }
                break;
            }
        }

        if (*notificationMetadataList == NULL) {
            *notificationMetadataList = p;
        } else {
            list_wptr->next = p;
        }

        list_wptr = p;
    }

    goto exit;

err:
    fret = -1;
    es10b_notification_metadata_list_free_all(*notificationMetadataList);
exit:
    free(respbuf);
    respbuf = NULL;
    return fret;
}

int es10b_retrieve_notifications_list(struct euicc_ctx *ctx, struct es10b_pending_notification *PendingNotification,
                                      unsigned long seqNumber) {
    int fret = 0;
    uint8_t seqNumber_buf[sizeof(seqNumber)];
    uint32_t seqNumber_buf_len = sizeof(seqNumber_buf);
    struct euicc_derutil_node n_request, n_searchCriteria, n_seqNumber;
    uint32_t reqlen;
    uint8_t *respbuf = NULL;
    unsigned resplen;

    struct euicc_derutil_node tmpnode, n_PendingNotification, n_NotificationMetadata;

    memset(PendingNotification, 0, sizeof(struct es10b_pending_notification));

    if (euicc_derutil_convert_long2bin(seqNumber_buf, &seqNumber_buf_len, seqNumber) < 0) {
        goto err;
    }

    memset(&n_request, 0, sizeof(n_request));
    memset(&n_searchCriteria, 0, sizeof(n_searchCriteria));
    memset(&n_seqNumber, 0, sizeof(n_seqNumber));

    n_request.tag = 0xBF2B; // RetrieveNotificationsListRequest
    n_request.pack.child = &n_searchCriteria;

    n_searchCriteria.tag = 0xA0; // searchCriteria
    n_searchCriteria.pack.child = &n_seqNumber;

    n_seqNumber.tag = 0x80; // seqNumber
    n_seqNumber.length = seqNumber_buf_len;
    n_seqNumber.value = seqNumber_buf;

    reqlen = sizeof(ctx->apdu._internal.request_buffer.body);
    if (euicc_derutil_pack(ctx->apdu._internal.request_buffer.body, &reqlen, &n_request)) {
        goto err;
    }

    if (es10x_command(ctx, &respbuf, &resplen, ctx->apdu._internal.request_buffer.body, reqlen) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&tmpnode, n_request.tag, respbuf, resplen) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&tmpnode, 0xA0, tmpnode.value, tmpnode.length) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_alias_tags(&n_PendingNotification, (uint16_t[]){0xBF37, 0x30}, 2, tmpnode.value,
                                             tmpnode.length)
        < 0) {
        goto err;
    }

    switch (n_PendingNotification.tag) {
    case 0xBF37: // profileInstallationResult
        if (euicc_derutil_unpack_find_tag(&tmpnode, 0xBF27, n_PendingNotification.value, n_PendingNotification.length)
            < 0) {
            goto err;
        }
        if (euicc_derutil_unpack_find_tag(&n_NotificationMetadata, 0xBF2F, tmpnode.value, tmpnode.length) < 0) {
            goto err;
        }
        break;
    case 0x30: // otherSignedNotification
        if (euicc_derutil_unpack_find_tag(&n_NotificationMetadata, 0xBF2F, n_PendingNotification.value,
                                          n_PendingNotification.length)
            < 0) {
            goto err;
        }
        break;
    }

    if (euicc_derutil_unpack_find_tag(&tmpnode, 0x0C, n_NotificationMetadata.value, n_NotificationMetadata.length)
        < 0) {
        goto err;
    }

    PendingNotification->notificationAddress = malloc(tmpnode.length + 1);
    if (!PendingNotification->notificationAddress) {
        goto err;
    }
    memcpy(PendingNotification->notificationAddress, tmpnode.value, tmpnode.length);
    PendingNotification->notificationAddress[tmpnode.length] = '\0';

    PendingNotification->b64_PendingNotification = malloc(euicc_base64_encode_len(n_PendingNotification.self.length));
    if (!PendingNotification->b64_PendingNotification) {
        goto err;
    }
    if (euicc_base64_encode(PendingNotification->b64_PendingNotification, n_PendingNotification.self.ptr,
                            n_PendingNotification.self.length)
        < 0) {
        goto err;
    }

    fret = 0;

    goto exit;

err:
    fret = -1;
    es10b_pending_notification_free(PendingNotification);
exit:
    free(respbuf);
    respbuf = NULL;
    return fret;
}

int es10b_remove_notification_from_list(struct euicc_ctx *ctx, unsigned long seqNumber) {
    int fret = 0;
    uint8_t seqNumber_buf[sizeof(seqNumber)];
    uint32_t seqNumber_buf_len = sizeof(seqNumber_buf);
    struct euicc_derutil_node n_request, n_seqNumber;
    uint32_t reqlen;
    uint8_t *respbuf = NULL;
    unsigned resplen;

    struct euicc_derutil_node tmpnode;

    if (euicc_derutil_convert_long2bin(seqNumber_buf, &seqNumber_buf_len, seqNumber) < 0) {
        goto err;
    }

    memset(&n_request, 0, sizeof(n_request));
    memset(&n_seqNumber, 0, sizeof(n_seqNumber));

    n_request.tag = 0xBF30; // NotificationSentRequest
    n_request.pack.child = &n_seqNumber;

    n_seqNumber.tag = 0x80; // seqNumber
    n_seqNumber.length = seqNumber_buf_len;
    n_seqNumber.value = seqNumber_buf;

    reqlen = sizeof(ctx->apdu._internal.request_buffer.body);
    if (euicc_derutil_pack(ctx->apdu._internal.request_buffer.body, &reqlen, &n_request)) {
        goto err;
    }

    if (es10x_command(ctx, &respbuf, &resplen, ctx->apdu._internal.request_buffer.body, reqlen) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&tmpnode, n_request.tag, respbuf, resplen) < 0) {
        goto err;
    }

    if (euicc_derutil_unpack_find_tag(&tmpnode, 0x80, tmpnode.value, tmpnode.length) < 0) {
        goto err;
    }

    fret = euicc_derutil_convert_bin2long(tmpnode.value, tmpnode.length);

    goto exit;

err:
    fret = -1;
exit:
    free(respbuf);
    respbuf = NULL;
    return fret;
}

void es10b_notification_metadata_list_free_all(struct es10b_notification_metadata_list *notificationMetadataList) {
    while (notificationMetadataList) {
        struct es10b_notification_metadata_list *next = notificationMetadataList->next;
        free(notificationMetadataList->notificationAddress);
        free(notificationMetadataList->iccid);
        free(notificationMetadataList);
        notificationMetadataList = next;
    }
}

void es10b_pending_notification_free(struct es10b_pending_notification *PendingNotification) {
    free(PendingNotification->notificationAddress);
    free(PendingNotification->b64_PendingNotification);
    memset(PendingNotification, 0, sizeof(struct es10b_pending_notification));
}

int es10b_get_rat(struct euicc_ctx *ctx, struct es10b_rat **ratList) {
    int fret;
    struct euicc_derutil_node n_request = {
        .tag = 0xBF43, // GetRatRequest
    };
    uint32_t reqlen;
    uint8_t *respbuf = NULL;
    unsigned resplen;

    struct es10b_rat *rat_list_wptr = NULL;
    struct euicc_derutil_node tmpnode, tmpchildnode, n_profile;

    *ratList = NULL;

    reqlen = sizeof(ctx->apdu._internal.request_buffer.body);
    if (euicc_derutil_pack(ctx->apdu._internal.request_buffer.body, &reqlen, &n_request)) {
        goto err;
    }

    if (es10x_command(ctx, &respbuf, &resplen, ctx->apdu._internal.request_buffer.body, reqlen) < 0) {
        goto err;
    }

    if (resplen == 0) {
        goto err;
    }

    // GetRatResponse
    if (euicc_derutil_unpack_find_tag(&tmpnode, 0xBF43, respbuf, resplen) < 0) {
        goto err;
    }

    // RulesAuthorisationTable
    if (euicc_derutil_unpack_find_tag(&tmpnode, 0xA0, tmpnode.value, tmpnode.length) < 0) {
        goto err;
    }

    n_profile.self.ptr = tmpnode.value;
    n_profile.self.length = 0;

    // ProfilePolicyAuthorisationRule
    while (euicc_derutil_unpack_next(&n_profile, &n_profile, tmpnode.value, tmpnode.length) == 0) {
        struct es10b_rat *rat;

        tmpchildnode.self.ptr = n_profile.value;
        tmpchildnode.self.length = 0;

        rat = malloc(sizeof(struct es10b_rat));
        if (!rat) {
            goto err;
        }

        memset(rat, 0, sizeof(*rat));

        while (euicc_derutil_unpack_next(&tmpchildnode, &tmpchildnode, n_profile.value, n_profile.length) == 0) {
            switch (tmpchildnode.tag) {
            case 0x80: // ppr ids
            {
                static const char *desc[] = {"pprUpdateControl", "ppr1", "ppr2", "ppr3", NULL};

                if (euicc_derutil_convert_bin2bits_str(&rat->pprIds, tmpchildnode.value, tmpchildnode.length, desc)) {
                    goto err;
                }
            } break;
            case 0xA1: { // allowed operators
                struct euicc_derutil_node n_allowed_operator, n_operator;
                struct es10b_operation_id *operations_wptr = NULL;
                struct es10b_operation_id *p;

                n_allowed_operator.self.ptr = tmpchildnode.value;
                n_allowed_operator.self.length = 0;

                while (euicc_derutil_unpack_next(&n_allowed_operator, &n_allowed_operator, tmpchildnode.value,
                                                 tmpchildnode.length)
                       == 0) {
                    p = malloc(sizeof(struct es10b_operation_id));
                    if (!p) {
                        goto err;
                    }
                    memset(p, 0, sizeof(*p));

                    n_operator.self.ptr = n_allowed_operator.value;
                    n_operator.self.length = 0;

                    while (euicc_derutil_unpack_next(&n_operator, &n_operator, n_allowed_operator.value,
                                                     n_allowed_operator.length)
                           == 0) {
                        if (n_operator.length == 0) {
                            continue;
                        }
                        switch (n_operator.tag) {
                        case 0x80: // mcc_mnc
                            p->plmn = malloc((n_operator.length * 2) + 1);
                            euicc_hexutil_bin2hex(p->plmn, (n_operator.length * 2) + 1, n_operator.value,
                                                  n_operator.length);
                            break;
                        case 0x81: // gid1
                            p->gid1 = malloc((n_operator.length * 2) + 1);
                            euicc_hexutil_bin2hex(p->gid1, (n_operator.length * 2) + 1, n_operator.value,
                                                  n_operator.length);
                            break;
                        case 0x82: // gid2
                            p->gid2 = malloc((n_operator.length * 2) + 1);
                            euicc_hexutil_bin2hex(p->gid2, (n_operator.length * 2) + 1, n_operator.value,
                                                  n_operator.length);
                            break;
                        }
                    }
                    if (operations_wptr == NULL) {
                        operations_wptr = p;
                    } else {
                        operations_wptr->next = p;
                    }
                }

                rat->allowedOperators = operations_wptr;
            } break;
            case 0x82: { // ppr flags
                static const char *desc[] = {"consentRequired", NULL};

                if (euicc_derutil_convert_bin2bits_str(&rat->pprFlags, tmpchildnode.value, tmpchildnode.length, desc)) {
                    goto err;
                }
            } break;
            }
        }

        if (*ratList == NULL) {
            *ratList = rat;
        } else {
            rat_list_wptr->next = rat;
        }

        rat_list_wptr = rat;
    }

    fret = 0;
    goto exit;
err:
    fret = -1;
    es10b_rat_list_free_all(*ratList);
    *ratList = NULL;
exit:
    free(respbuf);
    respbuf = NULL;
    return fret;
}

void es10b_rat_list_free_all(struct es10b_rat *ratList) {
    struct es10b_rat *next_rat;
    struct es10b_operation_id *next_operation_id;

    while (ratList) {
        next_rat = ratList->next;
        free(ratList->pprIds);
        while (ratList->allowedOperators) {
            next_operation_id = ratList->allowedOperators->next;
            free(ratList->allowedOperators->plmn);
            free(ratList->allowedOperators->gid1);
            free(ratList->allowedOperators->gid2);
            free(ratList->allowedOperators);
            ratList->allowedOperators = next_operation_id;
        }
        free(ratList->pprFlags);
        free(ratList);
        ratList = next_rat;
    }
}

int es10b_zk_profile_request_r(struct euicc_ctx *ctx, char **b64_ZKProfileResponse, const uint8_t *mnoChallenge,
                               uint32_t challengeLen) {
    int fret = 0;
    uint8_t reqbuf[21];
    uint8_t *respbuf = NULL;
    unsigned resplen;

    *b64_ZKProfileResponse = NULL;

    if (challengeLen != 16) {
        goto err;
    }

    /* BF42 { 80 10 <16B challenge> }, value len = 2 + 16 = 18 = 0x12 */
    reqbuf[0] = 0xBF;
    reqbuf[1] = 0x42;
    reqbuf[2] = 0x12;
    reqbuf[3] = 0x80;
    reqbuf[4] = 0x10;
    memcpy(reqbuf + 5, mnoChallenge, 16);

    if (es10x_command(ctx, &respbuf, &resplen, reqbuf, sizeof(reqbuf)) < 0) {
        goto err;
    }

    /* Verify outer tag is BF42 */
    if (resplen < 3 || respbuf[0] != 0xBF || respbuf[1] != 0x42) {
        goto err;
    }

    *b64_ZKProfileResponse = malloc(euicc_base64_encode_len(resplen));
    if (!*b64_ZKProfileResponse) {
        goto err;
    }
    if (euicc_base64_encode(*b64_ZKProfileResponse, respbuf, resplen) < 0) {
        goto err;
    }

    fret = 0;
    goto exit;

err:
    fret = -1;
    free(*b64_ZKProfileResponse);
    *b64_ZKProfileResponse = NULL;
exit:
    free(respbuf);
    respbuf = NULL;
    return fret;
}

int es10b_set_eligibility_data_r(struct euicc_ctx *ctx, const uint8_t *bf43_tlv, uint32_t bf43_len) {
    int fret = 0;
    uint8_t *respbuf = NULL;
    unsigned resplen;
    struct euicc_derutil_node n_outer, n_choice;

    if (es10x_command(ctx, &respbuf, &resplen, bf43_tlv, bf43_len) < 0) {
        goto err;
    }

    /* Response: BF43 { A0 { 30 {} } } for success, BF43 { A1 { INT } } for error */
    if (euicc_derutil_unpack_find_tag(&n_outer, 0xBF43, respbuf, resplen) < 0) {
        goto err;
    }
    if (euicc_derutil_unpack_find_tag(&n_choice, 0xA0, n_outer.value, n_outer.length) < 0) {
        goto err;
    }

    fret = 0;
    goto exit;

err:
    fret = -1;
exit:
    free(respbuf);
    respbuf = NULL;
    return fret;
}

static int b64_from_der_node(char **out, const struct euicc_derutil_node *node) {
    *out = malloc(euicc_base64_encode_len(node->length));
    if (!*out) {
        return -1;
    }
    if (euicc_base64_encode(*out, node->value, node->length) < 0) {
        free(*out);
        *out = NULL;
        return -1;
    }
    return 0;
}

/* Common encoder for the ZK control messages whose ASN.1 request body is one
 * context-0 field: ZkRegisterChallengeRequest, ZkRegisterCredentialRequest,
 * ZkCertInitRequest, and ZkCertInstallRequest.
 */
static int es10b_zk_send_single_field_request(struct euicc_ctx *ctx, uint16_t outer_tag, const uint8_t *field,
                                              uint32_t field_len, uint8_t **respbuf, unsigned *resplen) {
    int fret = 0;
    uint8_t *reqbuf = NULL;
    uint32_t reqlen;
    struct euicc_derutil_node n_request, n_field;

    memset(&n_request, 0, sizeof(n_request));
    memset(&n_field, 0, sizeof(n_field));

    n_request.tag = outer_tag;
    n_request.pack.child = &n_field;
    n_field.tag = 0x80;
    n_field.value = field;
    n_field.length = field_len;

    if (euicc_derutil_pack_alloc(&reqbuf, &reqlen, &n_request) < 0) {
        goto err;
    }
    if (es10x_command(ctx, respbuf, resplen, reqbuf, reqlen) < 0) {
        goto err;
    }

    goto exit;
err:
    fret = -1;
    free(*respbuf);
    *respbuf = NULL;
exit:
    free(reqbuf);
    return fret;
}

static int es10b_zk_expect_empty_ok_response(uint16_t outer_tag, const uint8_t *respbuf, unsigned resplen) {
    struct euicc_derutil_node n_outer, n_choice;

    if (euicc_derutil_unpack_find_tag(&n_outer, outer_tag, respbuf, resplen) < 0) {
        return -1;
    }
    if (euicc_derutil_unpack_find_tag(&n_choice, 0xA0, n_outer.value, n_outer.length) < 0) {
        return -1;
    }
    return 0;
}

int es10b_zk_register_challenge_r(struct euicc_ctx *ctx, struct es10b_zk_register_challenge_result *result,
                                  const uint8_t *mno_nonce_commitment, uint32_t mno_nonce_commitment_len) {
    int fret = 0;
    uint8_t *respbuf = NULL;
    unsigned resplen;
    struct euicc_derutil_node n_outer, n_choice, n_blinded_challenge, n_auth_sig;

    memset(result, 0, sizeof(*result));

    if (mno_nonce_commitment_len != 65) {
        goto err;
    }
    if (es10b_zk_send_single_field_request(ctx, 0xBF44, mno_nonce_commitment, mno_nonce_commitment_len,
                                           &respbuf, &resplen)
        < 0) {
        goto err;
    }
    if (euicc_derutil_unpack_find_tag(&n_outer, 0xBF44, respbuf, resplen) < 0 ||
        euicc_derutil_unpack_find_tag(&n_choice, 0xA0, n_outer.value, n_outer.length) < 0 ||
        euicc_derutil_unpack_find_tag(&n_blinded_challenge, 0x80, n_choice.value, n_choice.length) < 0 ||
        euicc_derutil_unpack_find_tag(&n_auth_sig, 0x81, n_choice.value, n_choice.length) < 0) {
        goto err;
    }
    if (n_blinded_challenge.length != 32) {
        goto err;
    }
    if (b64_from_der_node(&result->blindedEligibilityChallenge, &n_blinded_challenge) < 0 ||
        b64_from_der_node(&result->deviceAuthSignature, &n_auth_sig) < 0) {
        goto err;
    }

    goto exit;
err:
    fret = -1;
    es10b_zk_register_challenge_result_free(result);
exit:
    free(respbuf);
    return fret;
}

int es10b_zk_register_credential_r(struct euicc_ctx *ctx, const uint8_t *mno_partial_signature,
                                   uint32_t mno_partial_signature_len) {
    int fret = 0;
    uint8_t *respbuf = NULL;
    unsigned resplen;

    if (mno_partial_signature_len != 32) {
        goto err;
    }
    if (es10b_zk_send_single_field_request(ctx, 0xBF45, mno_partial_signature, mno_partial_signature_len,
                                           &respbuf, &resplen)
        < 0) {
        goto err;
    }
    if (es10b_zk_expect_empty_ok_response(0xBF45, respbuf, resplen) < 0) {
        goto err;
    }

    goto exit;
err:
    fret = -1;
exit:
    free(respbuf);
    return fret;
}

int es10b_zk_cert_init_request_r(struct euicc_ctx *ctx, struct es10b_zk_cert_init_result *result,
                                 const uint8_t *session_key_seed, uint32_t session_key_seed_len) {
    int fret = 0;
    uint8_t *respbuf = NULL;
    unsigned resplen;
    struct euicc_derutil_node n_outer, n_choice, n_user_pk, n_binding_sig, n_credential_hash;

    memset(result, 0, sizeof(*result));

    if (session_key_seed_len != 32) {
        goto err;
    }
    if (es10b_zk_send_single_field_request(ctx, 0xBF46, session_key_seed, session_key_seed_len,
                                           &respbuf, &resplen)
        < 0) {
        goto err;
    }
    if (euicc_derutil_unpack_find_tag(&n_outer, 0xBF46, respbuf, resplen) < 0 ||
        euicc_derutil_unpack_find_tag(&n_choice, 0xA0, n_outer.value, n_outer.length) < 0 ||
        euicc_derutil_unpack_find_tag(&n_user_pk, 0x80, n_choice.value, n_choice.length) < 0 ||
        euicc_derutil_unpack_find_tag(&n_binding_sig, 0x81, n_choice.value, n_choice.length) < 0 ||
        euicc_derutil_unpack_find_tag(&n_credential_hash, 0x82, n_choice.value, n_choice.length) < 0) {
        goto err;
    }
    if (n_user_pk.length != 65 || n_credential_hash.length != 32) {
        goto err;
    }
    if (b64_from_der_node(&result->userPublicKey, &n_user_pk) < 0 ||
        b64_from_der_node(&result->bindingSignature, &n_binding_sig) < 0 ||
        b64_from_der_node(&result->credentialBindingHash, &n_credential_hash) < 0) {
        goto err;
    }

    goto exit;
err:
    fret = -1;
    es10b_zk_cert_init_result_free(result);
exit:
    free(respbuf);
    return fret;
}

int es10b_zk_cert_install_r(struct euicc_ctx *ctx, const uint8_t *pseudonym_certificate,
                            uint32_t pseudonym_certificate_len) {
    int fret = 0;
    uint8_t *respbuf = NULL;
    unsigned resplen;

    if (!pseudonym_certificate || pseudonym_certificate_len == 0) {
        goto err;
    }
    if (es10b_zk_send_single_field_request(ctx, 0xBF47, pseudonym_certificate, pseudonym_certificate_len,
                                           &respbuf, &resplen)
        < 0) {
        goto err;
    }
    if (es10b_zk_expect_empty_ok_response(0xBF47, respbuf, resplen) < 0) {
        goto err;
    }

    goto exit;
err:
    fret = -1;
exit:
    free(respbuf);
    return fret;
}

void es10b_zk_register_challenge_result_free(struct es10b_zk_register_challenge_result *result) {
    if (!result) {
        return;
    }
    free(result->blindedEligibilityChallenge);
    free(result->deviceAuthSignature);
    result->blindedEligibilityChallenge = NULL;
    result->deviceAuthSignature = NULL;
}

void es10b_zk_cert_init_result_free(struct es10b_zk_cert_init_result *result) {
    if (!result) {
        return;
    }
    free(result->userPublicKey);
    free(result->bindingSignature);
    free(result->credentialBindingHash);
    result->userPublicKey = NULL;
    result->bindingSignature = NULL;
    result->credentialBindingHash = NULL;
}
