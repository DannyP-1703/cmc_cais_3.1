#include <stdio.h>

int
main(void)
{
    int                                 i;
    int                                 k = 0;

    for (i = 0; i != 15; ++i) {
        switch (i % 3)
        {
        case 0:
            printf("%2d is divisible by 3\n", i);
            break;

        case 1:
            ++k;

        case 2:
            printf("%2d is not divisible by 3\n", i);
            ++k;

            break;
        }
    }

    printf("Calculated k = %d\n", k);
    return 0;
}
