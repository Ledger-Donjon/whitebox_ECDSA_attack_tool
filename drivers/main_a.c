#include <stdio.h>
#include <stdint.h>
#include <string.h>

// gcc ../xx/source.c main.c -lgmp -fno-stack-protector

void ECDSA_256_sign(unsigned char sig[64], const unsigned char hash[32]);

int main(int argc, char *argv[]) {

    const uint8_t hash[32] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
    };
    
    uint8_t sig[64];
    
    ECDSA_256_sign(sig, hash);
    for (int i = 0; i < 64; i++) {
        printf("%02X", sig[i]);
    }
    printf("\n");
    
    return 0;
}
