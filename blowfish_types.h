#ifndef BLOWFISH_TYPES_H
#define	BLOWFISH_TYPES_H

#include <stdint.h>
#include <stdlib.h>

typedef struct bf_state_s bf_state;
struct bf_state_s
{
    uint32_t p_box[18];
    uint32_t s_box[4][256];
};

#endif	/* BLOWFISH_TYPES_H */
