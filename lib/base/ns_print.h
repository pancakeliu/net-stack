#ifndef _NETSTACK_BASE_PRINT_H_
#define _NETSTACK_BASE_PRINT_H_

#include <stdio.h>

#define NS_PRINT(format, ...) \
    do {                      \
        printf("%s:%s %s: "format, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
    } while (0)

#endif // _NETSTACK_BASE_PRINT_H_