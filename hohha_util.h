#ifndef HOHHA_UTIL_H
#define HOHHA_UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <syscall.h>
#include <unistd.h>

extern unsigned hohha_dbg_level;

#define pr(args...) fprintf(stderr, ##args)
#define dbg(args...) do { if (hohha_dbg_level) pr(args); } while (0)
#define vdbg(args...) do { if (hohha_dbg_level > 1) pr(args); } while (0)
#define vvdbg(args...) do { if (hohha_dbg_level > 2) pr(args); } while (0)

#ifndef getrandom
#define getrandom(args...) syscall(__NR_getrandom, ##args)
#endif

uint32_t crc32_byte(uint32_t crc, uint8_t word);
uint32_t crc32_data(uint8_t *data, uint32_t len);

int b64_encode(const uint8_t* data_buf, size_t data_len,
	       char* out_buf, size_t out_len);
int b64_decode(const char *in_buf, size_t in_len,
	       uint8_t *out_buf, size_t *out_len);

static inline uint32_t rol32(uint32_t word, unsigned shift)
{
	return (word << shift) | (word >> (32 - shift));
}

static inline uint32_t ror32(uint32_t word, unsigned shift)
{
	return (word >> shift) | (word << (32 - shift));
}

static inline uint32_t shl32(uint32_t word, unsigned shift)
{
	return word << shift;
}

static inline uint32_t bit32(unsigned shift)
{
	return 1u << shift;
}

static inline uint32_t incr32_mask(uint32_t word, uint32_t mask)
{
	unsigned shift, bit;

	for (shift = 0; shift < 32; ++shift) {
		bit = bit32(shift);
		if (bit & mask) {
			if (bit & word) {
				word &= ~bit;
			} else {
				word |= bit;
				break;
			}
		}
	}

	return word;
}

static inline uint8_t u8(uintmax_t word)
{
	return (uint8_t)word;
}

static inline uint32_t u32(uintmax_t word)
{
	return (uint32_t)word;
}

#endif
