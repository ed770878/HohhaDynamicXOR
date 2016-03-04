#ifndef HOHHA_PKT_H
#define HOHHA_PKT_H

#include <stdint.h>

#define HX_KEY_JMP_OFF	0
#define HX_KEY_JMP_SZ	1
#define HX_KEY_LEN_OFF	1
#define HX_KEY_LEN_SZ	2
#define HX_KEY_S1_OFF	3
#define HX_KEY_S1_SZ	4
#define HX_KEY_S2_OFF	7
#define HX_KEY_S2_SZ	4
#define HX_KEY_BODY_OFF	11

#define HX_PKT_ALS_OFF	0
#define HX_PKT_ALS_SZ	1
#define HX_PKT_DUM_OFF	1
#define HX_PKT_DUM_SZ	1
#define HX_PKT_S1_OFF	2
#define HX_PKT_S1_SZ	4
#define HX_PKT_S2_OFF	6
#define HX_PKT_S2_SZ	4
#define HX_PKT_CRC_OFF	10
#define HX_PKT_CRC_SZ	4
#define HX_PKT_PAD_OFF	14
#define HX_PKT_PAD_SZ	1
#define HX_PKT_ALN_OFF	15

#endif
