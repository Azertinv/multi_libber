# multi_libber

A script to automatically add a prefix to every exported symbol of an archive or object.  
If the --patch option is used, patch every symbol in the file that match a name in the patch list file.

## example

```
➜  tests git:(master) ✗ cat main.c
#include <stdio.h>

void ayylmao(void);

int main(void)
{
    ayylmao();
}
➜  tests git:(master) ✗ cat test.c 
#include <stdio.h>

void ayylmao(void)
{
    printf("ayylmao\n");
}
➜  tests git:(master) ✗ clang -c test.c
➜  tests git:(master) ✗ multi_libber ~/tools/musl/lib/libc.a traced_libc.a traced_func.txt
parsing obj files
retrieving symbols to patch
applying symbol prefix patch
writing result
➜  tests git:(master) ✗ grep '^printf$' traced_func.txt
printf
➜  tests git:(master) ✗ nm traced_libc.a| grep '[0-9]printf.lo' -A 3 
931printf.lo:
0000000000000000 T __traced_printf
                 U __traced___stdout_FILE
                 U __traced_vfprintf
➜  tests git:(master) ✗ nm test.o 
0000000000000000 T ayylmao
0000000000000000 r .L.str
                 U printf
➜  tests git:(master) ✗ multi_libber test.o test.o traced_func.txt --patch                                   
retrieving symbols to patch
applying symbol prefix patch
writing result
➜  tests git:(master) ✗ nm test.o
0000000000000000 T ayylmao
0000000000000000 r .L.str
                 U __traced_printf
➜  tests git:(master) ✗ clang main.c test.o traced_libc.a
➜  tests git:(master) ✗ ./a.out 
ayylmao
➜  tests git:(master) ✗ objdump -S a.out
...
0000000000001140 <ayylmao>:
    1140:       55                      push   %rbp
    1141:       48 89 e5                mov    %rsp,%rbp
    1144:       48 8d 3d b9 2e 00 00    lea    0x2eb9(%rip),%rdi        # 4004 <_IO_stdin_used+0x4>
    114b:       b0 00                   mov    $0x0,%al
    114d:       e8 02 00 00 00          callq  1154 <__traced_printf>
    1152:       5d                      pop    %rbp
    1153:       c3                      retq   
...
```
