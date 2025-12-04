#include <stdio.h>

static int
is_prime(int n)
{
    int                                 i;

    for (i = 2; i * i <= n; ++i) {
        if (0 == n % i) {
            return 0;
        }
    }

    return 1;
}

int
main(void)
{
    int                                 i;

    for (i = 1; i != 100; ++i) {
        if (is_prime(i)) {
            printf("%2d is prime!\n", i);
        } else {
            printf("%2d is not prime.\n", i);
        }
    }

    return 0;
}
