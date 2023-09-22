///
/// File: Example of a library adapter for tracing with dr_model
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <stdlib.h>

void function_under_test(int a)
{
    int *array = malloc(10 * sizeof(int));
    int t = array[a % 10];
}

void __attribute__((noinline)) revizor_test_case(int a)
{
    function_under_test(a);
}

int main(int argc, char const *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <int>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    revizor_test_case(atoi(argv[1]));

    return 0;
}
