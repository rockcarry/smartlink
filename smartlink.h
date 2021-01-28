#ifndef __SMARTLINK_H__
#define __SMARTLINK_H__

#include <stdint.h>

void* smartlinktx_init(char *dev);
void  smartlinktx_exit(void *ctx);
void  smartlinktx_send(void *ctx, uint8_t *buf, int len); // max send size is 42 bytes

typedef int (*PFN_SMARTLINK_CALLBCK)(int channel, uint8_t *mac, uint8_t *buf, int len);
void* smartlinkrx_init(char *dev);
void  smartlinkrx_exit(void *ctx);
void  smartlinkrx_recv(void *ctx, int channel, uint8_t *mac, int sniffetmin, int sniffetmax, PFN_SMARTLINK_CALLBCK callback);

#endif
