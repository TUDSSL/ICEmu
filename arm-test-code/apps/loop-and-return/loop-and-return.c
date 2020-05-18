volatile int var = 10;

int main(void)
{
    for (int i=0; i<10; i++) {
        var += 1;
    }

    return var;
}
