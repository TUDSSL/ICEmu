#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define STR(a) #a

#define DEBUG_FUZZEMU
#ifdef DEBUG_FUZZEMU
#define Dprintf(format, ...) \
    fprintf(stderr, format, ##__VA_ARGS__)
#else
#define Dprintf(...)
#endif

#include <unicorn/unicorn.h>
#include <capstone.h>

//#include "elf_symbols_gen.h"

static void dump_regs(uc_engine *uc);
uint32_t addr_base, addr_len;

static int fd_in = 0;
static int fd_out = 1;
static int use_pipe = 0;
static int flag_display_insn = 0;

/* capstone ahndle */
static csh cs_handle;

static uint32_t nop_cnt;

static void display_instrucion(uc_engine *uc, uint64_t address, uint32_t
        size, unsigned *should_skip_this)
{
    cs_insn *insn;
    size_t cnt;
    uint8_t insn_buf[size];
    uc_err err;
    size_t j;

    /* read code */
    err = uc_mem_read(uc, address, insn_buf, size);
    assert(!err && "failed mem read (insn)");

    /* disas code */
    cnt = cs_disasm(cs_handle, insn_buf, size, address, 0, &insn);
    if (cnt > 0) {
        for (j = 0; j < cnt; j++) {
            if (flag_display_insn)
                fprintf(stderr, "\t%"PRIx64":\t%s\t\t%s\n", insn[j].address,
                        insn[j].mnemonic,
                        insn[j].op_str);
            if (!strcmp("mov", insn[j].mnemonic) && !strcmp("r0, r0", insn[j].op_str)) {
                //fprintf(stderr, "NOP @0x%08x\n", insn[j].address);
                ++nop_cnt;
                if (nop_cnt % 100000 == 0) {
                    fprintf(stderr, "nops: %d\n", nop_cnt);
                }
            } else if (!strcmp("udf.w", insn[j].mnemonic)) {
                fprintf(stderr, "Got udf\n");
                *should_skip_this = 1;
            } else if (!strcmp("bx", insn[j].mnemonic)) {
                Dprintf("got bx\n");
                dump_regs(uc);
            } else if (!strcmp("strd", insn[j].mnemonic)) {
                Dprintf("got strd\n");
                dump_regs(uc);
            } else if (!strcmp("ldr", insn[j].mnemonic)) {
                Dprintf("got ldr\n");
                dump_regs(uc);
            } else if (!strcmp("mov", insn[j].mnemonic)) {
                Dprintf("got mov\n");
                dump_regs(uc);
            }
            if (cs_insn_group(cs_handle, &insn[j], CS_GRP_JUMP)) {
                /* fprintf(stderr, "\t\tjmp^^^\n"); */
            }
        }
    } else {
        fprintf(stderr,
                "XXX: failed to dissas @0x%08x %02hhx%02hhx (size=%u)\n",
                (uint32_t)address, insn_buf[0], insn_buf[1], size);
    }

    cs_free(insn, cnt);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uint8_t bytes[2*size];
    uc_err err;
    uint32_t pc;


    Dprintf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);

    err = uc_mem_read(uc, address, bytes, size);
    assert(!err && "failed mem read");

    if (bytes[0] == 0xff && bytes[1] == 0xf7) {
        Dprintf("quirk for insn 0xfff7\n");
        /* quirk: capstone reports 2 bytes insn size here */
        size = 4;
        err = uc_mem_read(uc, address, bytes, size);
        assert(!err && "failed mem read");
    } else if (bytes[0] == 0x00 && bytes[1] == 0xf0) {
        Dprintf("quirk for insn 0x00f0\n");
        /* quirk: capstone reports 2 bytes insn size here */
        size = 4;
        err = uc_mem_read(uc, address, bytes, size);
        assert(!err && "failed mem read");
    } else {
        /* cortex-m32 quirks for insn size */
        /* http://stackoverflow.com/questions/28860250/how-to-determine-if-a-word4-bytes-is-a-16-bit-instruction-or-32-bit-instructio
        */
#define M 0xf8
#define A 0xf8
#define B 0xf0
#define C 0xe8
        uint8_t r = bytes[1] & M;
        if (r == A || r == B || r == C) {
            Dprintf("generic quirk for insn %02hhx%02hhx\n",
                    bytes[0], bytes[1]);
            size = 4;
        }
    }

    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    Dprintf("pc@%08x[insn=%02x%02x]\n", pc, bytes[0], bytes[1]);

    unsigned should_skip_this = 0;
    /* disas instruction at pc */
    display_instrucion(uc, address, size, &should_skip_this);
    if (should_skip_this) {
        uint32_t new_pc = pc + size + 1;
        uc_reg_write(uc, UC_ARM_REG_PC, &new_pc);
    }
    /* actual instruction skip policy */
}


static void dump_regs(uc_engine *uc)
{
#define PRINT_REG(RN) do { \
    uint32_t reg_val_##RN; \
    uc_reg_read(uc, UC_ARM_REG_##RN, &reg_val_##RN); \
    Dprintf(STR(RN) ":0x%08x", reg_val_##RN); \
} while (0)

Dprintf(">>> ");
PRINT_REG(PC); Dprintf(" "); PRINT_REG(LR); Dprintf(" "); PRINT_REG(SP);
Dprintf("\n");

Dprintf(">>> ");
PRINT_REG(R0); Dprintf(" "); PRINT_REG(R1); Dprintf(" "); PRINT_REG(R2);
Dprintf("\n");

Dprintf(">>> ");
PRINT_REG(R3); Dprintf(" "); PRINT_REG(R4); Dprintf(" "); PRINT_REG(R5);
Dprintf("\n");
}


typedef uint32_t armaddr_t;
typedef struct segment {
    const char *const name;
    armaddr_t origin;
    armaddr_t length;
} segment_t;

// Corresponds to the MEMORY field in the linker script
segment_t Memory[] = {
    {
        .name = "ROMEM",
        //.addr_min = 0xc000,
        .origin = 0xc000,
        .length = (960*1024),
    },
    {
        .name = "RWMEM",
        .origin = 0x10000000,
        .length = (384*1024),
    },
    {
        .name = "NVMEM",
        .origin = 0x51000000,
        .length = (512*1024),
    },
};
#define SEGMENTS_TOTAL() (sizeof(Memory)/sizeof(segment_t))

static inline armaddr_t align_addr(armaddr_t addr, armaddr_t align)
{
    addr = ((addr + align-1) / align) * align;
    return addr;
}

// Map an address range to memory (make sure it actually fits)
static void map_to_memory(armaddr_t *lowp, armaddr_t *highp)
{
    segment_t *s;
    armaddr_t low, high;
    int has_changed = 0;

    low = *lowp;
    high = *highp;

    for (size_t i=0; i<SEGMENTS_TOTAL(); i++) {
        s = &Memory[i];

        armaddr_t s_low = s->origin;
        armaddr_t s_high = s->origin+s->length;

        if ((low >= s_low && low <= s_high) || high >= s_low && high <= s_high) {
            // One of the points is in the memory range.
            // Cut off stuff thats outside
            if (low < s_low) {
                low = s_low;
                has_changed = 1;
            }

            if (high > s_high) {
                high = s_high;
                has_changed = 1;
            }
            Dprintf("Placed range [0x%08x-0x%08x] in %s\n", low, high, s->name);
            *lowp = low;
            *highp = high;
            return;
        }
    }
}


static int load_segment_in_unicorn(uc_engine *uc, void *elf_buf, Elf *e, size_t segm_num)
{
    GElf_Phdr phdr;
    uc_err err;

    armaddr_t low, high, size;

    if (gelf_getphdr(e, segm_num, &phdr) != &phdr)
        errx(EXIT_FAILURE, "getphdr() failed: %s.",
                elf_errmsg(-1));

    low = phdr.p_paddr;
    high = phdr.p_memsz + phdr.p_paddr;

    // Adjust the segment to the memory. This is to solve the issue that the elf
    // parser thinks the memory start at 0x0.
    armaddr_t offset = low;
    map_to_memory(&low, &high);
    size = high - low;

    offset = low - offset;

    Dprintf("load segment: [0x%08x-0x%08x](type=%s, off=0x%08x)\n",
            low, high,
            ((phdr.p_type == PT_LOAD) ? "PT_LOAD" : "?"),
            (uint32_t)phdr.p_offset);

    err = uc_mem_write(uc, low, &((uint8_t*)elf_buf)[phdr.p_offset+offset], size);
    assert(!err && "failed mem write");
    return err;
}

static void memory_map(uc_engine *uc)
{
    for (size_t s=0; s<SEGMENTS_TOTAL(); s++) {
        armaddr_t orig = Memory[s].origin;
        armaddr_t len = align_addr(Memory[s].length, 1024);

        printf("Map memory segment: %s : ORIGIN = 0x%08x, LENGTH = 0x%08x\n",
                Memory[s].name, orig, len);

        uc_err err = uc_mem_map(uc, orig, len, UC_PROT_ALL);
        if (err) {
            Dprintf("Failed on uc_mem_map() with error returned: %u (%s)\n",
                    err, uc_strerror(err));
        }
    }
}

static void memory_init(uc_engine *uc, const char *path_to_elf)
{
    struct stat elf_stat;
    int fd, i;
    void *elf_buf;
    Elf *e;
    size_t n;
    GElf_Phdr phdr;

    uc_err err;

    if (elf_version(EV_CURRENT) == EV_NONE)
        errx(EXIT_FAILURE, "ELF library initialization "
                "failed: %s", elf_errmsg(-1));

    if ((fd = open(path_to_elf, O_RDONLY, 0)) < 0)
        errx(EXIT_FAILURE, "open \"%s\" failed", path_to_elf);

    if (fstat(fd, &elf_stat) < 0) {
        perror("fstat()");
    }

    elf_buf = malloc(elf_stat.st_size);
    assert(elf_buf != NULL);

    if (read(fd, elf_buf, elf_stat.st_size) != elf_stat.st_size) {
        perror("read()");
    }

    if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
        errx(EXIT_FAILURE, "elf_begin() failed: %s.",
                elf_errmsg(-1));

    if (elf_kind(e) != ELF_K_ELF)
        errx(EXIT_FAILURE, "\"%s\" is not an ELF object.",
                path_to_elf);

    // Done parsing ELF

    /* Get the number of segments */
    if (elf_getphdrnum(e, &n) != 0)
        errx(EXIT_FAILURE, "elf_getphdrnum() failed: %s.",
                elf_errmsg(-1));

    /* load segments */
    for (i = 0; i < n; i++) {
        load_segment_in_unicorn(uc, elf_buf, e, i);
    }

    free(elf_buf);
    close(fd);
}

#if 0
static void load_elf_in_unicorn(uc_engine *uc, const char *path_to_elf)
{

    uint32_t addr_min, addr_max;
    struct stat elf_stat;
    int fd, i;
    void *elf_buf;
    Elf *e;
    size_t n;
    GElf_Phdr phdr;
    uc_err err;

    /* map elf: get min address and max address
     * alocate buffer
     * copy things inplace
     * min address p_paddr
     * max address p_paddr+p_memsz
     * min address p
     * Map each segment [p_paddr; p_paddr+p_filesz] (assume the rest 0)
     */

    /* get addr_min and addr_max to map */
    addr_max = 0;
    addr_min = UINT_MAX;

    if (elf_version(EV_CURRENT) == EV_NONE)
        errx(EXIT_FAILURE, "ELF library initialization "
                "failed: %s", elf_errmsg(-1));

    if ((fd = open(path_to_elf, O_RDONLY, 0)) < 0)
        errx(EXIT_FAILURE, "open \"%s\" failed", path_to_elf);

    if (fstat(fd, &elf_stat) < 0) {
        perror("fstat()");
        goto failed_fstat;
    }

    elf_buf = malloc(elf_stat.st_size);
    assert(elf_buf != NULL);

    if (read(fd, elf_buf, elf_stat.st_size) != elf_stat.st_size) {
        perror("read()");
        goto failed_read;
    }

    if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
        errx(EXIT_FAILURE, "elf_begin() failed: %s.",
                elf_errmsg(-1));

    if (elf_kind(e) != ELF_K_ELF)
        errx(EXIT_FAILURE, "\"%s\" is not an ELF object.",
                path_to_elf);

    if (elf_getphdrnum(e, &n) != 0)
        errx(EXIT_FAILURE, "elf_getphdrnum() failed: %s.",
                elf_errmsg(-1));

    for (i = 0; i < n; i++) {
        if (gelf_getphdr(e, i, &phdr) != &phdr)
            errx(EXIT_FAILURE, "getphdr() failed: %s.",
                    elf_errmsg(-1));
        if (phdr.p_paddr < addr_min)
            addr_min = phdr.p_paddr;
        if (phdr.p_paddr+phdr.p_memsz > addr_max)
            addr_max = phdr.p_paddr+phdr.p_memsz;
    }

    addr_base = addr_min;
    addr_len = addr_max-addr_min;

#define ALIGN_SZ 1024
    addr_len = ((addr_len + ALIGN_SZ-1) /
            ALIGN_SZ) * ALIGN_SZ;
#undef ALIGN_SZ

    Dprintf("mapping elf from [0x%08x-0x%08x](len=0x%08x)\n", addr_min, addr_max, addr_len);
    err = uc_mem_map(uc, addr_base, addr_len, UC_PROT_ALL);
    if (err) {
        Dprintf("Failed on uc_mem_map() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        goto failed_uc_map;
    }
    /* TODO: is this needed?  */
    void *zero_buf = calloc(addr_len, 1);
    uc_mem_write(uc, addr_base, zero_buf, addr_len);



    /* load segments */
    for (i = 0; i < n; i++) {
        load_segment_in_unicorn(uc, elf_buf, e, i);
    }

    free(zero_buf);


failed_uc_map:
    elf_end(e);
failed_read:
    free(elf_buf);
failed_fstat:
    close(fd);
}
#endif

int main(int argc, char **argv, char **envp)
{
    uc_err err;
    uc_hook trace_code;
    uc_engine *uc;
    uint32_t sp, addr_start;
    int i;

    err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS, &uc);
    if (err) {
        Dprintf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return -1;
    }

    memory_map(uc);
    memory_init(uc, "../arm-test-code/build/apps/loop-and-return/loop-and-return.elf");

    /* initialize capstone engine */
    if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS, &cs_handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize capstone engine\n");
        return -1;
    }
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    /* install hooks */
    uc_hook_add(uc, &trace_code, UC_HOOK_CODE, hook_code, NULL, 0x0000c000, 1024);

    /* set stack */
    sp = 0x1005fff8;
    uc_reg_write(uc, UC_ARM_REG_SP, &sp);

    /* start emulation */
    fprintf(stderr, "emulation started\n");
    //err = uc_emu_start(uc, symbol_my_main|1, addr_base+addr_len, 0, 0);
    addr_start = 0xc12c;
    err = uc_emu_start(uc, addr_start|1, 0xc154, 0, 0);
    if (err) {
        Dprintf("Failed on uc_emu_start() with error returned: %u: %s\n", err, uc_strerror(err));
    }

    dump_regs(uc);
    uc_close(uc);

    return 0;
}
