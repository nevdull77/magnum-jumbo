/*
 * generic salted-sha1 support for LDAP style password storage
 * only works with salt that are powers of 2
 *
 * by bartavelle?
 * XXX: need a licensing statement
 */

#define MAX_SALT_LEN	16

#include <string.h>

#include "misc.h"
#include "formats.h"
#include "arch.h"
#ifdef HAVE_MPI
#include "john-mpi.h"
#endif

#ifdef SHA1_SSE_PARA
#define MMX_COEF	4
#include "sse-intrinsics.h"
#define NBKEYS	(MMX_COEF * SHA1_SSE_PARA)
#elif MMX_COEF
#define NBKEYS	MMX_COEF
#endif

#include "common.h"

#include "sha.h"
#include "base64.h"

#define FORMAT_LABEL			"salted-sha1"
#define FORMAT_NAME			"Salted SHA-1"

#ifdef SHA1_N_STR
#define ALGORITHM_NAME			"SSE2i " SHA1_N_STR
#elif defined(MMX_COEF) && MMX_COEF == 4
#define ALGORITHM_NAME			"SSE2 4x"
#elif defined(MMX_COEF) && MMX_COEF == 2
#define ALGORITHM_NAME			"MMX 2x"
#elif defined(MMX_COEF)
#define ALGORITHM_NAME			"?"
#else
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		48

#define BINARY_SIZE			20
#define SALT_SIZE			(MAX_SALT_LEN + sizeof(unsigned int))

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
//#define GETPOS(i, index)		( (index&3)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + (3-((i)&3)) + (index>>2)*80*MMX_COEF*4 ) //for endianity conversion
//#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + (3-((i)&(MMX_COEF-1))) + (index>>(MMX_COEF>>1))*80*MMX_COEF*4 ) //for endianity conversion
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + (3-((i)&3)) + (index>>(MMX_COEF>>1))*80*MMX_COEF*4 ) //for endianity conversion
//#define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + (3-((i)&3)) )
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#define NSLDAP_MAGIC "{ssha}"
#define NSLDAP_MAGIC_LENGTH 6

struct s_salt
{
	unsigned int len;
	union {
		unsigned char c[MAX_SALT_LEN];
		ARCH_WORD_32 w32;
	} data;
};

static struct s_salt saved_salt;

static struct fmt_tests tests[] = {
// Test hashes originally(?) in OPENLDAPS_fmt (openssha) (salt length 4)
	{"{SSHA}bPXG4M1KkwZh2Hbgnuoszvpat0T/OS86", "thales"},
	{"{SSHA}hHSEPW3qeiOo5Pl2MpHQCXh0vgfyVR/X", "test1"},
	{"{SSHA}pXp4yIiRmppvKYn7cKCT+lngG4qELq4h", "test2"},
	{"{SSHA}Bv8tu3wB8WTMJj3tcOsl1usm5HzGwEmv", "test3"},
	{"{SSHA}kXyh8wLCKbN+QRbL2F2aUbkP62BJ/bRg", "lapin"},
	{"{SSHA}rnMVxsf1YJPg0L5CBhbVLIsJF+o/vkoE", "canard"},
	{"{SSHA}Uf2x9YxSWZZNAi2t1QXbG2PmT07AtURl", "chien"},
	{"{SSHA}XXGLZ7iKpYSBpF6EwoeTl27U0L/kYYsY", "hibou"},
	{"{SSHA}HYRPmcQIIzIIg/c1L8cZKlYdNpyeZeml", "genou"},
	{"{SSHA}Zm/0Wll7rLNpBU4HFUKhbASpXr94eSTc", "caillou"},
	{"{SSHA}Qc9OB+aEFA/mJ5MNy0AB4hRIkNiAbqDb", "doudou"},

// Test vectors originally in NSLDAPS_fmt (ssha) (salt length 8)
	{"{SSHA}WTT3B9Jjr8gOt0Q7WMs9/XvukyhTQj0Ns0jMKQ==", "Password9"},
	{"{SSHA}ypkVeJKLzbXakEpuPYbn+YBnQvFmNmB+kQhmWQ==", "qVv3uQ45"},
	{"{SSHA}cKFVqtf358j0FGpPsEIK1xh3T0mtDNV1kAaBNg==", "salles"},
	{"{SSHA}W3ipFGmzS3+j6/FhT7ZC39MIfqFcct9Ep0KEGA==", "asddsa123"},
	{"{SSHA}YbB2R1D2AlzYc9wk/YPtslG7NoiOWaoMOztLHA==", "ripthispassword"},
#if 0
/*
 * These two were found in john-1.6-nsldaps4.diff.gz and apparently they were
 * supported by that version of they code, but they are not anymore.
 */
  {"{SSHA}/EExmSfmhQSPHDJaTxwQSdb/uPpzYWx0ZXI=", "secret"},
  {"{SSHA}gVK8WC9YyFT1gMsQHTGCgT3sSv5zYWx0", "secret"},
#endif

	{NULL}
};

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key SALT_SHA_saved_key
#define crypt_key SALT_SHA_crypt_key
#ifdef _MSC_VER
__declspec(align(16)) unsigned char saved_key[80*4*NBKEYS];
__declspec(align(16)) unsigned char crypt_key[BINARY_SIZE*NBKEYS];
#else
unsigned char saved_key[80*4*NBKEYS] __attribute__ ((aligned(16)));
unsigned char crypt_key[BINARY_SIZE*NBKEYS] __attribute__ ((aligned(16)));
#endif
static unsigned int saved_len[NBKEYS];
static unsigned char out[PLAINTEXT_LENGTH + 1];
static unsigned int salt_sizes;
static unsigned int max_salt_size;
#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
static SHA_CTX ctx;
#endif

static void init(struct fmt_main *pFmt)
{
#ifdef MMX_COEF
	salt_sizes = 0;
	max_salt_size = 0;
#endif
}

static void * binary(char *ciphertext) {
	static char *realcipher;

	if (!realcipher) realcipher = mem_alloc_tiny(BINARY_SIZE + 9, MEM_ALIGN_WORD);

	/* stupid overflows */
	memset(realcipher, 0, BINARY_SIZE + 9);
	base64_decode(NSLDAP_MAGIC_LENGTH+ciphertext, strlen(ciphertext)-NSLDAP_MAGIC_LENGTH, realcipher);
// if we try to unify the rawsha1_cmp_one() and and rawsha1_cmp_all() functions, we should endian alter for all MMX_COEF.
// Right now, for MMX/SSE non-para, we keep the older methods.
#ifdef SHA1_SSE_PARA
	alter_endianity((unsigned char *)realcipher, BINARY_SIZE);
#endif
	return (void *)realcipher;
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
//	printf("%s %s\n", __func__, ciphertext);
	if(strlen(ciphertext) > (CIPHERTEXT_LENGTH + NSLDAP_MAGIC_LENGTH) )
		return 0;
	return !strncasecmp(ciphertext, NSLDAP_MAGIC, NSLDAP_MAGIC_LENGTH);
}

static int binary_hash_0(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xf; }
static int binary_hash_1(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xff; }
static int binary_hash_2(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfff; }
static int binary_hash_3(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffff; }
static int binary_hash_4(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfffff; }
static int binary_hash_5(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffffff; }
static int binary_hash_6(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0x7ffffff; }

static void set_key(char *key, int index) {
#ifdef MMX_COEF
	int len;
	int i;

	if(index==0)
	{
		memset(saved_len, 0, sizeof(saved_len));
		//memset(saved_key, 0, sizeof(saved_key));
		i = 0;
#ifdef SHA1_SSE_PARA
		for (; i < SHA1_SSE_PARA; ++i)
#endif
			memset(&saved_key[i*4*80*MMX_COEF], 0, 56*MMX_COEF);
	}
	len = strlen(key);
	if(len>PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;
	saved_len[index] = len;

	for(i=0;i<len;i++)
		saved_key[GETPOS(i, index)] = key[i];


	saved_key[GETPOS(i, index)] = 0x80;
	((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*80*MMX_COEF] = len<<3;

#else
	strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
#endif
}

static void * get_salt(char * ciphertext)
{
	static struct s_salt cursalt;
	char realcipher[BINARY_SIZE + (MAX_SALT_LEN*4/3) + 9];

//	printf("%s %s\n", __func__, ciphertext);

	memset(realcipher, 0, sizeof(realcipher));
	memset(&cursalt, 0, sizeof(struct s_salt));
	base64_decode(NSLDAP_MAGIC_LENGTH+ciphertext, strlen(ciphertext) - NSLDAP_MAGIC_LENGTH, realcipher);
	switch( strlen(ciphertext ) )
	{
		case 38:
			cursalt.len = 4;
			break;
		case 46:
			cursalt.len = 8;
			break;
		default:
#ifdef HAVE_MPI
			if (mpi_id == 0)
#endif
			fprintf(stderr, "unknown salt size for %s (total len=%ld)\n", ciphertext, (long)strlen(ciphertext));
			return NULL;
	}
#ifdef MMX_COEF
	salt_sizes |= cursalt.len;
	if(cursalt.len > max_salt_size)
		max_salt_size = cursalt.len;
#endif
	memcpy(cursalt.data.c, realcipher+BINARY_SIZE, cursalt.len);
	return &cursalt;
}

static char *get_key(int index) {
#ifdef MMX_COEF
	unsigned int i,s;

//	s = ((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*80*MMX_COEF] >> 3;
	s = saved_len[index];
	for(i=0;i<s;i++)
		out[i] = saved_key[ GETPOS(i, index) ];
	out[i] = 0;
	return (char *) out;
#else
	return saved_key;
#endif
}

static int cmp_all(void *binary, int count) {
#ifdef MMX_COEF
# ifdef SHA1_SSE_PARA
	unsigned int x,y=0;

#ifdef SHA1_SSE_PARA
	for(;y<SHA1_SSE_PARA;y++)
#endif
	for(x=0;x<MMX_COEF;x++)
	{
		if( ((unsigned int *)binary)[0] == ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] )
			return 1;
	}
	return 0;
# else
	int i=0;
	while(i< (BINARY_SIZE/4) )
	{
		if (
			( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF])
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+1])
#   if (MMX_COEF > 3)
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+2])
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+3])
#   endif
		)
			return 0;
		i++;
	}
	return 1;
# endif
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int count){
  return (1);
}

static int cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
# if SHA1_SSE_PARA
	unsigned int x,y;
        x = index&3;
        y = index/4;

        if( ((unsigned int *)binary)[0] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] )
                return 0;
        if( ((unsigned int *)binary)[1] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5+4] )
                return 0;
        if( ((unsigned int *)binary)[2] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5+8] )
                return 0;
        if( ((unsigned int *)binary)[3] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5+12] )
                return 0;
        if( ((unsigned int *)binary)[4] != ((unsigned int *)crypt_key)[x+y*MMX_COEF*5+16] )
                return 0;
        return 1;
# else
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+index] )
			return 0;
	return 1;
# endif
#else
	return cmp_all(binary, index);
#endif
}


static void set_salt(void *salt) {
	memcpy(&saved_salt, salt, sizeof(struct s_salt));
/*
data is not a pointer, so this check did not make sense
	if(saved_salt.data == NULL)
		printf("data is NULL\n");
*/
}

#ifdef MMX_COEF
static void set_onesalt(int index)
{
	unsigned int i;
	for(i=0;i<saved_salt.len;i++)
		saved_key[GETPOS(i + saved_len[index], index)] = saved_salt.data.c[i];
	if(saved_salt.len != max_salt_size) /* more than one salt size at the same time */
		for(i=0;i<max_salt_size-saved_salt.len;i++)
			saved_key[GETPOS(i+saved_salt.len+saved_len[index], index)] = 0;

	saved_key[GETPOS(saved_salt.len + saved_len[index], index)] = 0x80;

	((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*80*MMX_COEF] = (saved_salt.len + saved_len[index])<<3;
}
#endif

static void crypt_all(int count) {
#ifdef MMX_COEF
	unsigned int i;
	for(i=0;i<NBKEYS;i++)
		set_onesalt(i);
# if SHA1_SSE_PARA
	SSESHA1body(saved_key, (unsigned int *)crypt_key, NULL, 0);
# else
	shammx_nosizeupdate((unsigned char *) crypt_key, (unsigned char *) saved_key, 1);

# endif

#else
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, (unsigned char *) saved_key, strlen( saved_key ) );
	SHA1_Update( &ctx, (unsigned char *) saved_salt.data.c, saved_salt.len);
	SHA1_Final( (unsigned char *) crypt_key, &ctx);
//	dump_stuff((unsigned char *)crypt_key, 20);
//	exit(1);
#endif

}

#ifdef MMX_COEF
static int get_hash_0(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] & 0xf;
}
static int get_hash_1(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] & 0xff;
}
static int get_hash_2(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] & 0xfff;
}
static int get_hash_3(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] & 0xffff;
}
static int get_hash_4(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] & 0xfffff;
}
static int get_hash_5(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] & 0xffffff;
}
static int get_hash_6(int index)
{
	unsigned int x,y;
        x = index&3;
        y = index/4;
	return ((unsigned int *)crypt_key)[x+y*MMX_COEF*5] & 0x7ffffff;
}
#else
static int get_hash_0(int index) { return ((unsigned int *)crypt_key)[0] & 0xf; }
static int get_hash_1(int index) { return ((unsigned int *)crypt_key)[0] & 0xff; }
static int get_hash_2(int index) { return ((unsigned int *)crypt_key)[0] & 0xfff; }
static int get_hash_3(int index) { return ((unsigned int *)crypt_key)[0] & 0xffff; }
static int get_hash_4(int index) { return ((unsigned int *)crypt_key)[0] & 0xfffff; }
static int get_hash_5(int index) { return ((unsigned int *)crypt_key)[0] & 0xffffff; }
static int get_hash_6(int index) { return ((unsigned int *)crypt_key)[0] & 0x7ffffff; }
#endif

static int salt_hash(void *salt)
{
	struct s_salt * mysalt = salt;
	return mysalt->data.w32 & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_saltedsha = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		get_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2,
			binary_hash_3,
			binary_hash_4,
			binary_hash_5,
			binary_hash_6
		},
		salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};