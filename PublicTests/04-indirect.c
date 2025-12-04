#include <stdio.h>

typedef int (*pf)(int);

static int
fi(int x)
{
    printf("+ %d\n", x);

    return x + 1;
}

static int
ft(int x)
{
    printf("* %d\n", x);

    return 2 * x;
}

static int
fs(int x)
{
    printf("^ %d\n", x);

    return x * x;
}

static pf seq[] = { fi, ft, fi, fs, ft, fi, fs, NULL};

int
main(void)
{
    int                                 x = 1;
    pf *                                f;

    for (f = seq; *f; ++f) {
        x = (*f)(x);
    }

    printf("= %d\n", x);

    return 0;
}
