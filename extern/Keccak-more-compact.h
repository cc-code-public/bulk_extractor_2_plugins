//~ https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-more-compact.c
//~ void FIPS202_SHA3_256(const u8 *in, u64 inLen, u8 *out) { Keccak(1088, 512, in, inLen, 0x06, out, 32); }
//~ --> Use 0x01 as delimited suffix (pure Keccak)
//~ void FIPS202_SHA3_256(const u8 *in, u64 inLen, u8 *out) { Keccak(1088, 512, in, inLen, 0x01, out, 32); }

#define FOR(i,n) for(i=0; i<n; ++i)
typedef unsigned char u8;
typedef unsigned long long int u64;
typedef unsigned int ui;

void Keccak(ui r, ui c, const u8 *in, u64 inLen, u8 sfx, u8 *out, u64 outLen);
void FIPS202_SHA3_256(const u8 *in, u64 inLen, u8 *out);
int LFSR86540(u8 *R);

#define ROL(a,o) ((((u64)a)<<o)^(((u64)a)>>(64-o)))
#define rL(x,y) load64((u8*)s+8*(x+5*y))
#define wL(x,y,l) store64((u8*)s+8*(x+5*y),l)
#define XL(x,y,l) xor64((u8*)s+8*(x+5*y),l)
