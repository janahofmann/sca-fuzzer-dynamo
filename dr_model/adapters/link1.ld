REGISTER_INIT_SIZE = 0x1000;
MAIN_REGION_SIZE = 0x1000;
FAULTY_REGION_SIZE = 0x1000;
OVERFLOW_REGION_SIZE = 0x1000;

ENTRY(_start)

MEMORY {
    data (rw) :      ORIGIN = 0x1000 ,      LENGTH = 2M
    text (rx) :      ORIGIN = code_start,   LENGTH = 1M
    sandbox(rw) :    ORIGIN = sandbox_base, LENGTH = 1M
}

SECTIONS {
    .data : { *(.data) } > data
    .bss : { *(.bss) } > data
    .init_array :
    {
        PROVIDE_HIDDEN (__init_array_start = .);
        KEEP (*(SORT(.init_array.*)))
        KEEP (*(.init_array ))
        PROVIDE_HIDDEN (__init_array_end = .);
    } > data

    .text : {
        *(.test_case)
        . = ALIGN(0x8000);
        *(.text)
    } > text

    __lower_overflow = ORIGIN(sandbox);
    __main_base = __lower_overflow + OVERFLOW_REGION_SIZE;
    __upper_overflow = __main_base + MAIN_REGION_SIZE + FAULTY_REGION_SIZE;
    __upper_overflow_end = __upper_overflow + OVERFLOW_REGION_SIZE;

    .sandbox.lower_overflow (__lower_overflow) :
    {
        _szero = .;
        . = . + OVERFLOW_REGION_SIZE - 1;
    } > sandbox =0


    .sandbox (__main_base):
    {
        *(.sandbox)
    } > sandbox

}
