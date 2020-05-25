volatile int var = 10;

int main(void)
{
    while (1) {
        var += 1;
    }

    return var;
}
