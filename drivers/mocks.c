#include <time.h>

clock_t clock() {
    static clock_t n = 123456;
    n += 123;
    return n;
}

time_t time( time_t * pTime ) {
    if (pTime) {
        *pTime = 1600000000;
    }    
    return 1600000000;
}