#include <stdio.h>
#include "utils.h"

void print_attack_note(void)
{
    printf("========================================\n");
    printf("  All your important files have been encrypted.\n");
    printf("  This is a simulated ransomware for OS assignment.\n");
    printf("  Use the correct password with 'restore' mode to recover.\n");
    printf("========================================\n");
}

void print_restore_note(void)
{
    printf("========================================\n");
    printf("  All target files have been successfully restored.\n");
    printf("  Thank you for using the OS assignment ransomware demo.\n");
    printf("========================================\n");
}
