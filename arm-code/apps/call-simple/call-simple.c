#include <stdint.h>

volatile int var = 0;

uint32_t call_simple(uint32_t value1, uint16_t value2) {
  return value1 * value2;
}

int main(void)
{
    var = call_simple(10, 20);

    return var;
}
