#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

extern void test_case_enter(void);

#define xstr(s) _str(s)
#define _str(s) str(s)
#define str(s) #s

#define MAX_TEST_CASE_SIZE 0x10000

// Sandbox
#define MAIN_REGION_SIZE 4096
#define FAULTY_REGION_SIZE 4096
#define OVERFLOW_REGION_SIZE 4096
#define INPUT_SIZE (MAIN_REGION_SIZE + FAULTY_REGION_SIZE + OVERFLOW_REGION_SIZE)

#define REG_INIT_OFFSET 0x2000
#define REG_INITIALIZATION_REGION_SIZE 0x40
#define SIMD_INIT_OFFSET (REG_INIT_OFFSET + REG_INITIALIZATION_REGION_SIZE)

typedef struct Sandbox {
    char dbg_trap_region1[4096];               // region for trapping underflows
    char lower_overflow[OVERFLOW_REGION_SIZE]; // zero-initialized region for accidental overflows
    char main_region[MAIN_REGION_SIZE];        // first input page. does not cause faults
    char faulty_region[FAULTY_REGION_SIZE];    // second input. causes a (configurable) fault
    char upper_overflow[OVERFLOW_REGION_SIZE]; // zero-initialized region for accidental overflows
    char dbg_trap_region2[4096];               // region for trapping overflows
} sandbox_t;

sandbox_t *sandbox = NULL;
uint8_t *test_case = NULL;

void __attribute__((noinline)) revizor_test_case(void)
{
    asm volatile(
        "push %%rax\n"
        "push %%rbx\n"
        "push %%rcx\n"
        "push %%rdx\n"
        "push %%rsi\n"
        "push %%rdi\n"
        "pushfq\n"

        "mov %[sandbox], %%r14\n"
        "mov %[tc], %%r15\n" // clang-format off
        "mov "xstr(REG_INIT_OFFSET + 0x30)"(%%r14), %%rax\n"         // clang-format off
        "push %%rax\n"
        "popfq\n"
        "mov "xstr(REG_INIT_OFFSET + 0x00)"(%%r14), %%rax\n"         // clang-format off
        "mov "xstr(REG_INIT_OFFSET + 0x08)"(%%r14), %%rbx\n"         // clang-format off
        "mov "xstr(REG_INIT_OFFSET + 0x10)"(%%r14), %%rcx\n"         // clang-format off
        "mov "xstr(REG_INIT_OFFSET + 0x18)"(%%r14), %%rdx\n"         // clang-format off
        "mov "xstr(REG_INIT_OFFSET + 0x20)"(%%r14), %%rsi\n"         // clang-format off
        "mov "xstr(REG_INIT_OFFSET + 0x28)"(%%r14), %%rdi\n"         // clang-format off
        "vmovdqa "xstr(SIMD_INIT_OFFSET + 0x00)"(%%r14), %%ymm0\n"   // clang-format off
        "vmovdqa "xstr(SIMD_INIT_OFFSET + 0x20)"(%%r14), %%ymm1\n"   // clang-format off
        "vmovdqa "xstr(SIMD_INIT_OFFSET + 0x40)"(%%r14), %%ymm2\n"   // clang-format off
        "vmovdqa "xstr(SIMD_INIT_OFFSET + 0x60)"(%%r14), %%ymm3\n"   // clang-format off
        "vmovdqa "xstr(SIMD_INIT_OFFSET + 0x80)"(%%r14), %%ymm4\n"   // clang-format off
        "vmovdqa "xstr(SIMD_INIT_OFFSET + 0xa0)"(%%r14), %%ymm5\n"   // clang-format off
        "vmovdqa "xstr(SIMD_INIT_OFFSET + 0xc0)"(%%r14), %%ymm6\n"   // clang-format off
        "vmovdqa "xstr(SIMD_INIT_OFFSET + 0xe0)"(%%r14), %%ymm7\n"   // clang-format off
        "callq *%%r15\n"

        "popfq\n"
        "pop %%rdi\n"
        "pop %%rsi\n"
        "pop %%rdx\n"
        "pop %%rcx\n"
        "pop %%rbx\n"
        "pop %%rax\n"

        :
        : [sandbox] "r"(&sandbox->main_region[0]), [tc] "r"(test_case)
        : "r14", "r15");
}

// A function that opens a binary file, reads its contents, appends a return opcode, and calls it as
// a function
int load_test_case(const char *filename)
{
    // Open the file in binary mode
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    // Get the file size by seeking to the end and telling the position
    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    if (size > MAX_TEST_CASE_SIZE) {
        fprintf(stderr, "ERROR: test case is too large\n");
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0, SEEK_SET);

    // Read the file contents into the buffer
    if (fread(test_case, 1, size, fp) != size) {
        perror("fread");
        exit(EXIT_FAILURE);
    }

    // Close the file
    fclose(fp);

    // Append a return opcode to the end of the buffer
    // Assuming x86 architecture, the return opcode is C3 in hex
    test_case[size] = '\xC3';
}

int main(int argc, char const *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <test case file> <shm buffer>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    sandbox = (sandbox_t *)aligned_alloc(0x10000, sizeof(sandbox_t));
    mprotect(sandbox->dbg_trap_region1, 4096, PROT_NONE);
    mprotect(sandbox->dbg_trap_region2, 4096, PROT_NONE);

    test_case = (uint8_t *)aligned_alloc(0x10000, MAX_TEST_CASE_SIZE);
    mprotect(test_case, MAX_TEST_CASE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
    load_test_case(argv[1]);


    // open the shared memory
    int input_buffer = shm_open(argv[2], O_RDONLY, 0);
    if ((input_buffer == -1)) {
        perror("shm_open");
        exit(EXIT_FAILURE);
    }

    // get the size of the input buffer
    struct stat st;
    if (fstat(input_buffer, &st) == -1) {
        perror("fstat");
        exit(EXIT_FAILURE);
    }
    size_t size = st.st_size;
    // assert(size % INPUT_SIZE == 0);
    if (size % INPUT_SIZE != 0) {
        fprintf(stderr, "ERROR: input buffer size is not a multiple of %d\n", INPUT_SIZE);
        exit(EXIT_FAILURE);
    }

    // map the shared memory object into memory
    unsigned char *input_mapped = mmap(NULL, size, PROT_READ, MAP_SHARED, input_buffer, 0);
    if (input_mapped == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    // set the input and execut the test case
    for (int i = 0; i < size; i += INPUT_SIZE) {
        memset(&sandbox->lower_overflow[0], 0, OVERFLOW_REGION_SIZE);
        memcpy(sandbox->main_region, input_mapped + i, INPUT_SIZE);
        revizor_test_case();
    }

    // cleanup
    if (munmap(input_mapped, size) == -1) {
        perror("munmap");
        exit(EXIT_FAILURE);
    }
    if (close(input_buffer) == -1) {
        perror("close");
        exit(EXIT_FAILURE);
    }
    free(sandbox);
    free(test_case);

    return 0;
}
