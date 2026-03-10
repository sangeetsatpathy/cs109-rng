#include "ringbuffer.h"
#include "malloc.h"
#include "strings.h"
#include "rng.h"
#include "printf.h"
#include "timer.h"

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// SHA-256 Sigma0 function: ROTR7(x) ^ ROTR18(x) ^ (x >> 3)
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))

// SHA-256 Sigma1 function: ROTR17(x) ^ ROTR19(x) ^ (x >> 10)
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static struct {
    volatile int* base;
    volatile int* currPos;
    int isInitialized;
    int maxSize;
} timingRbq;

void pool_insert(int val){
    *(timingRbq.currPos) = val; 
    
    timingRbq.currPos += 1;
    if(timingRbq.currPos == timingRbq.base + timingRbq.maxSize){
        //then we've gone too far, reset the currPos.
        timingRbq.currPos = timingRbq.base;
    }
}

void randomInit(){
    //malloc a chunk of memory for keeping an "entropy pool"; 
    //essentially, these entropy pools should hold timer data; 
    //milliseconds is probably a long. long values are 64-bit, or 8-bytes long.

    //use RBQ, of length 500!

    //if(timingRbq.isInitialized == 1){
        //then free current memory!
    //    free(timingRbq.base);
        //return;
    //}
   
    timingRbq.base = (int*) malloc(2048); //4000 = 4 (int) * 512 (we need 512 keypresses)
    timingRbq.maxSize = 2048 / sizeof(int);
    printf("initialized %p \n", timingRbq.base);
    //memset(timingRbq.base, 0, 2048);
    timingRbq.currPos = timingRbq.base;
    timingRbq.isInitialized = 1;
    
    // rngPool.hashValues[0] = 0x6a09e667;
    // rngPool.hashValues[1] = 0xbb67ae85;
    // rngPool.hashValues[2] = 0x3c6ef372;
    // rngPool.hashValues[3] = 0xa54ff53a;
    // rngPool.hashValues[4] = 0x510e527f;
    // rngPool.hashValues[5] = 0x9b05688c;
    // rngPool.hashValues[6] = 0x1f83d9ab;
    // rngPool.hashValues[7] = 0x5be0cd19;

}

//note: we process the entropy pool in terms of 512 bit blocks; in other words, arrays of 16 ints! So our queue is represented by 32 of these
struct block{
    int arr[16];
};


int choice(int s, int a, int b) {
    return (s & a) ^ (~s & b);
}

/**
 * Expands 16-word (512-bit) block into a 64-word SHA-256 message schedule.
 * @param W Pointer to an array of 64 uint32_t elements.
 *          Indices 0-15 must be pre-filled with the message block data.
 */
void sha256_expand_message(int W[64]) {
    for (int i = 16; i < 64; i++) {
        // The expansion uses addition modulo 2^32 (handled naturally by uint32_t)
        W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
    }
}

int custom_stack_hash(int message[64], int top) {
    // Initial "Top of Stack" (Initial Vector)
    // We use a constant so the hash of an empty message isn't 0
    for (int i = 0; i < 64; i++) {
        int current_word = message[i];

        // Part 1: Choice(switch=word, a=top<<<7, b=word>>>7)
        int term1 = choice(current_word, ROTL(top, 7), ROTR(current_word, 7));

        // Part 2: Choice(switch=word, a=top<<<11, b=word>>>11)
        int term2 = choice(current_word, ROTL(top, 11), ROTR(current_word, 11));

        // Combine using Modular Addition (+) to create carries and non-linearity
        // This updates the "Top of Stack" for the next itera   tion
        top = term1 + term2 + current_word;
    }

    return top;
}


int randomGenerator(){
    //every integer in the queue is its own 'message'! we need to process the words in 32 bit chunks
    //struct block msg[32];
    static int top = 0x6A09E667; 
    top ^= (int) timer_get_ticks();
    int currHash;
    for(int i = 0; i < 32; i++){
        struct block currBlock = *((struct block*)(timingRbq.base) + i);
        int messageSchedules[64];
        for(int k = 0; k < 16; k++){
            messageSchedules[k] = currBlock.arr[k];
        }
        sha256_expand_message(messageSchedules); //fill up the message schedule

        //now process my current message schedule into an integer hash
        currHash = custom_stack_hash(messageSchedules, top);
        top = currHash;
    }
    return top;
}

