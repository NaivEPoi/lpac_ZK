#include "zk-download.h"
#include "main.h"

#include <euicc/es10b.h>
#include <euicc/es9p.h>
#include <euicc/euicc.h>
#include <euicc/tostr.h>
#include <lpac/utils.h>

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *opt_string = "s:m:h?";

static volatile int cancelled = 0;

#define CANCELPOINT() \
    if (cancelled) {  \
        goto err;     \
    }

static void sigint_handler(__attribute__((unused)) int x) { cancelled = 1; }

static int applet_main(int argc, char **argv) {
    int fret;
    const char *error_function_name = NULL;
    _cleanup_free_ char *error_detail = NULL;

    int opt;
    char *smdp = NULL;
    char *matchingId = NULL;

    struct es10b_load_bound_profile_package_result download_result = {0};

    while ((opt = getopt(argc, argv, opt_string)) != -1) {
        switch (opt) {
        case 's':
            smdp = strdup(optarg);
            break;
        case 'm':
            matchingId = strdup(optarg);
            break;
        case 'h':
        case '?':
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("\t -s SM-DP+ Address (required; from profile zk-order)\n");
            printf("\t -m Matching ID (required; from profile zk-order)\n");
            printf("\t -h This help info\n");
            return -1;
        default:
            break;
        }
    }

    if (!smdp || strlen(smdp) == 0) {
        error_function_name = "smdp";
        error_detail = strdup("required");
        goto err;
    }

    if (!matchingId || strlen(matchingId) == 0) {
        error_function_name = "matchingId";
        error_detail = strdup("required");
        goto err;
    }

    cancelled = 0;
    signal(SIGINT, sigint_handler);

    euicc_ctx.http.server_address = smdp;

    /* Profile download: zk-order has already completed the MNO/ZK exchange. */
    CANCELPOINT();
    jprint_progress("es10b_get_euicc_challenge_and_info", smdp);
    if (es10b_get_euicc_challenge_and_info(&euicc_ctx)) {
        error_function_name = "es10b_get_euicc_challenge_and_info";
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es9p_initiate_authentication", smdp);
    if (es9p_initiate_authentication(&euicc_ctx)) {
        error_function_name = "es9p_initiate_authentication";
        error_detail = strdup(euicc_ctx.http.status.message);
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es10b_authenticate_server", smdp);
    if (es10b_authenticate_server(&euicc_ctx, matchingId, NULL)) {
        error_function_name = "es10b_authenticate_server";
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es9p_authenticate_client", smdp);
    if (es9p_authenticate_client(&euicc_ctx)) {
        error_function_name = "es9p_authenticate_client";
        error_detail = strdup(euicc_ctx.http.status.message);
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es10b_prepare_download", smdp);
    if (es10b_prepare_download(&euicc_ctx, NULL)) {
        error_function_name = "es10b_prepare_download";
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es9p_get_bound_profile_package", smdp);
    if (es9p_get_bound_profile_package(&euicc_ctx)) {
        error_function_name = "es9p_get_bound_profile_package";
        error_detail = strdup(euicc_ctx.http.status.message);
        goto err;
    }

    CANCELPOINT();
    jprint_progress("es10b_load_bound_profile_package", smdp);
    if (es10b_load_bound_profile_package(&euicc_ctx, &download_result)) {
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "%s,%s",
                 euicc_bppcommandid2str(download_result.bppCommandId),
                 euicc_errorreason2str(download_result.errorReason));
        error_function_name = "es10b_load_bound_profile_package";
        error_detail = strdup(buffer);
        goto err;
    }

    jprint_success(NULL);

    fret = 0;
    goto exit;

err:
    fret = -1;
    es10b_cancel_session(&euicc_ctx, ES10B_CANCEL_SESSION_REASON_ENDUSERREJECTION);
    es9p_cancel_session(&euicc_ctx);
    if (cancelled) {
        jprint_error("cancelled", NULL);
    } else {
        jprint_error(error_function_name, error_detail);
    }
exit:
    free(smdp);
    free(matchingId);
    euicc_http_cleanup(&euicc_ctx);
    return fret;
}

struct applet_entry applet_profile_zk_download = {
    .name = "zk-download",
    .main = applet_main,
};
