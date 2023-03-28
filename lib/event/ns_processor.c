#include <string.h>
#include <stdio.h>

#include <rte_malloc.h>

#include <event/ns_processor.h>
#include <proto/ns_arp.h>

ns_processor *new_processor()
{
    ns_processor *processor = rte_malloc(
        "net-stack processor",
        sizeof(struct ns_processor),
        0
    )
    if (processor == NULL) {
        printf("%s: rte_malloc exec failed.\n", __FUNCTION__);
        return NULL;
    }
    bzero(processor, sizeof(struct ns_processor));

    ns_arp_table *arp_table = create_arp_table();
    if (arp_table == NULL) {
        printf("%s: create arp table failed.\n", __FUNCTION__);
        return NULL;
    }
    processor->arp_table = arp_table;

    return processor;
}

int register_server(ns_processor_t *processor, ns_server_t *server)
{
    
}