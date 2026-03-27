/* Simple test DLL for VXEngine
 * Compile: cl /LD /Od test_simple.c /Fe:test_simple.dll
 */
#include <windows.h>
#include <stdio.h>

__declspec(dllexport) int add_numbers(int a, int b) {
    return a + b;
}

__declspec(dllexport) int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

__declspec(dllexport) void xor_decrypt(char* buf, int len, char key) {
    for (int i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

/* Simple "VM" - dispatch table with function pointers */
typedef int (*handler_func)(int arg);

static int handler_add(int arg) { return arg + 10; }
static int handler_mul(int arg) { return arg * 3; }
static int handler_sub(int arg) { return arg - 5; }
static int handler_xor(int arg) { return arg ^ 0xFF; }

static handler_func dispatch_table[4] = {
    handler_add, handler_mul, handler_sub, handler_xor
};

__declspec(dllexport) int vm_execute(int opcode, int arg) {
    if (opcode >= 0 && opcode < 4) {
        return dispatch_table[opcode](arg);
    }
    return -1;
}

BOOL WINAPI DllMain(HINSTANCE hDLL, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        /* Simple init: compute a value using malloc */
        int* p = (int*)malloc(sizeof(int));
        if (p) {
            *p = 42;
            free(p);
        }
    }
    return TRUE;
}
