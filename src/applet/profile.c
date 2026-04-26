#include "profile.h"

#include "main.h"
#include "profile/delete.h"
#include "profile/disable.h"
#include "profile/discovery.h"
#include "profile/download.h"
#include "profile/enable.h"
#include "profile/list.h"
#include "profile/nickname.h"
#include "profile/zk-certinit.h"
#include "profile/zk-download.h"
#include "profile/zk-order.h"
#include "profile/zk-register.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const struct applet_entry *applets[] = {
    &applet_profile_list,   &applet_profile_enable,    &applet_profile_disable,   &applet_profile_nickname,
    &applet_profile_delete, &applet_profile_download,  &applet_profile_discovery,
    &applet_profile_zk_register, &applet_profile_zk_certinit, &applet_profile_zk_order,
    &applet_profile_zk_download, NULL,
};

static int applet_main(const int argc, char **argv) {
    const int ret = main_init_euicc();
    if (ret != 0)
        return ret;
    return applet_entry(argc, argv, applets);
}

struct applet_entry applet_profile = {
    .name = "profile",
    .main = applet_main,
};
