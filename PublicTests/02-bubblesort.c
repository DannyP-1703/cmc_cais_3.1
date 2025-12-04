#include <stdio.h>

static int a[] = { 3, 7, 1, 8, 1024, 0 };
static int b[] = { 9, 1, 1, 4, 3, 0, 2 };

static void
bubblesort(int *a, size_t n)
{
    size_t                              i, j;
    int                                 t;

    for (i = 0; i != n; ++i) {
        for (j = n - 1; j != i; --j) {
            if (a[j] < a[j - 1]) {
                t = a[j]; a[j] = a[j - 1]; a[j - 1] = t;
            }
        }
    }
}

static void
print(const int *a, size_t n)
{
    size_t                              i;

    for (i = 0; i != n; ++i) {
        printf("%d ", a[i]);
    }

    printf("\n");
}

int
main(void)
{
    size_t                              i;

    bubblesort(a, sizeof(a) / sizeof(a[0]));
    bubblesort(b, sizeof(b) / sizeof(b[0]));

    print(a, sizeof(a) / sizeof(a[0]));
    print(b, sizeof(b) / sizeof(b[0]));

    return 0;
}
