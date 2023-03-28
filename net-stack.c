#include <ns_dpdk_if.h>
#include <ns_config.h>
#include <error/ns_error.h>

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

    // create net-stack processor
    ns_processor *processor = create_processor();
    if (processor == NULL) {
        printf("net-stack create processor failed..\n");
        return -1;
    }

    ret = ns_dpdk_start(&dpdk_meta, processor);
    if (ret != NS_OK) {
        printf("net-stack start dpdk worker failed. err:%s..\n", ns_strerror(ret));
        return ret;
    }

    return 0;
}