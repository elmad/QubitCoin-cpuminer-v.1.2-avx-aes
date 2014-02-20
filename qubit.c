#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "x5/luffa_for_sse2.h" //sse2 opt
//#include "x5/luffa/ssse3_x64asm-PS-2/luffa_for_x64asm.h"
//--ch h----
#include "x5/cubehash_sse2.h" //sse2
//----------
#include "x5/sph_shavite.h"
//#include "x5/low-mem/SHA3api_ref.h"
//-----simd vect128---------
#include "x5/vect128/nist.h"
//---echo ----------------
#define _ECHO_VPERM_
#define AES-NI
#include "x5/echo512/ccalik/aesni/hash_api.h"

#if defined(__GNUC__)
	#define  DATA_ALIGN(x,y) x __attribute__ ((aligned(y)))
#else
	#define DATA_ALIGN(x,y) __declspec(align(y)) x
#endif
/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
	hashState_luffa luffa1;
	cubehashParam cubehash1;
	sph_shavite512_context  shavite1;
	hashState_echo		echo1;
	hashState_sd simd1;
} qubithash_context_holder;

qubithash_context_holder base_contexts;

void init_qubithash_contexts()
{
  //-- luffa init --
  init_luffa(&base_contexts.luffa1,512);
  //--cubehash init--
  cubehashInit(&base_contexts.cubehash1,512,16,32);
  //---------------
  sph_shavite512_init(&base_contexts.shavite1);
   //-------------------------------
  init_echo(&base_contexts.echo1, 512);
  //--simd init----
  init_sd(&base_contexts.simd1,512);
}

static void qubithash(void *state, const void *input)
{
	qubithash_context_holder ctx;

	DATA_ALIGN(uint32_t hashA[32], 16);
	uint32_t *hashB = hashA + 16;
	memcpy(&ctx, &base_contexts, sizeof(base_contexts));

	//-------luffa sse2--------
	update_luffa(&ctx.luffa1,(const BitSequence *)input,640);
	final_luffa(&ctx.luffa1,(BitSequence *)hashA);	
    //---cubehash sse2---    
	cubehashUpdate(&ctx.cubehash1,(const byte *)hashA,64);
	cubehashDigest(&ctx.cubehash1,(byte *)hashB);
  //------shavite  ------	
	sph_shavite512 (&ctx.shavite1, hashB, 64);   
	sph_shavite512_close(&ctx.shavite1, hashA);  
 //Hash_sh(512,(const BitSequence *)hashB,512,(BitSequence *)hashA);
//-------simd512 vect128 --------------	
	update_sd(&ctx.simd1,(const BitSequence *)hashA,512);
	final_sd(&ctx.simd1,(BitSequence *)hashB);
//-----------------	
	update_echo (&ctx.echo1, (const BitSequence *) hashB, 512);   
        final_echo(&ctx.echo1, (BitSequence *)hashA); 

	memcpy(state, hashA, 32);
	
}

int scanhash_qubit(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint32_t hash64[8] __attribute__((aligned(32)));
	uint32_t endiandata[32];
	
	
	int kk=0;
	for (; kk < 32; kk++)
	{
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	};

	if (ptarget[7]==0) {
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			qubithash(hash64, &endiandata);
			if (((hash64[7]&0xFFFFFFFF)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else if (ptarget[7]<=0xF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			qubithash(hash64, &endiandata);
			if (((hash64[7]&0xFFFFFFF0)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else if (ptarget[7]<=0xFF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			qubithash(hash64, &endiandata);
			if (((hash64[7]&0xFFFFFF00)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else if (ptarget[7]<=0xFFF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			qubithash(hash64, &endiandata);
			if (((hash64[7]&0xFFFFF000)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	

	} 
	else if (ptarget[7]<=0xFFFF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			qubithash(hash64, &endiandata);
			if (((hash64[7]&0xFFFF0000)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	

	} 
	else 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			qubithash(hash64, &endiandata);
			if (fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	}
	
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
