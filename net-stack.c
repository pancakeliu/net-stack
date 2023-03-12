#include "lib/ns_dpdk_if.h"
#include "lib/ns_config.h"
#include "lib/ns_error.h"

int main(int argc, char **argv) {
    struct ns_dpdk_meta dpdk_meta;
    struct ns_config    config;
    ns_config_default(&config);

    int ret = ns_dpdk_init(argc, argv, &config, &dpdk_meta);
    if (ret != NS_OK) {
        printf("net-stack dpdk init failed. err:%s..\n", ns_strerror(ret));
        return ret;
    }

    printf("hello world....\n");

    return 0;
}