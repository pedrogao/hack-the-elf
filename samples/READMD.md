## hello

```sh
$ xxd < hello | head

$ xxd < hello | tail -60 | head

$ xxd < hello | tail -32 | head
```

小端序号：

```sh
$ # -s = seek, -l = length
$ xxd -s 62 -l 2 ./hello
000003e: 0500                                     ..
```

查询目标符号：

```sh
$ # -g = group size
$ xxd -s 40 -l 8 -g 8 ./hello
0000028: 5802000000000000                   X.......

$ echo $((0x2140))
8512
```

```sh
$ ndisasm -b 64 ./hello | less

$ ndisasm -b 64 -k 0,$((0x000000AF)) ./a.out

$ dd if=./a.out skip=$((0x000000AF)) bs=1 count=$((0x30)) | ndisasm -b 64 -
```

```sh
$ pmap 20951
20951:   /home/pedro/workspace/cpp/hack-the-elf/samples/a.out
0000000000400000      4K r-x-- a.out
0000000000600000      8K rw--- a.out
00007ffff7ddb000    132K r-x-- ld-2.17.so
00007ffff7ffa000      8K r-x--   [ anon ]
00007ffff7ffc000      8K rw--- ld-2.17.so
00007ffff7ffe000      4K rw---   [ anon ]
00007ffffffdd000    136K rw---   [ stack ]
ffffffffff600000      4K r-x--   [ anon ]
 total              304K

$ cat /proc/21971/maps
00400000-00401000 r-xp 00000000 fc:01 6045406                            /home/pedro/workspace/cpp/hack-the-elf/samples/a.out
00600000-00602000 rw-p 00000000 fc:01 6045406                            /home/pedro/workspace/cpp/hack-the-elf/samples/a.out
7ffff7ddb000-7ffff7dfc000 r-xp 00000000 fc:01 24864                      /usr/lib64/ld-2.17.so
7ffff7ffa000-7ffff7ffc000 r-xp 00000000 00:00 0                          [vdso]
7ffff7ffc000-7ffff7ffe000 rw-p 00021000 fc:01 24864                      /usr/lib64/ld-2.17.so
7ffff7ffe000-7ffff7fff000 rw-p 00000000 00:00 0
7ffffffdd000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```

这个鬼的编译器，竟然把 const 修饰的常量放在了可以执行的内存中，哈哈哈。

```sh
$ objdump -d ./a.out | less
$ nm ./a.out
```

In 64-bit mode, NASM will by default generate absolute addresses. The REL keyword makes it produce RIP–relative addresses. Since this is frequently the normally desired behaviour, see the DEFAULT directive (section 6.2). The keyword ABS overrides REL.

```sh
$ nasm -f elf64 hello-pie.asm
$ objdump -d hello-pie.o

hello-pie.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <_start>:
   0:   bf 01 00 00 00          mov    $0x1,%edi
   5:   48 be 00 00 00 00 00    movabs $0x0,%rsi
   c:   00 00 00
   f:   ba 09 00 00 00          mov    $0x9,%edx
  14:   b8 01 00 00 00          mov    $0x1,%eax
  19:   0f 05                   syscall
  1b:   48 31 ff                xor    %rdi,%rdi
  1e:   b8 3c 00 00 00          mov    $0x3c,%eax
  23:   0f 05                   syscall
$ nasm -f elf64 hello-pie.asm
$ objdump -d hello-pie.o

hello-pie.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <_start>:
   0:   bf 01 00 00 00          mov    $0x1,%edi
   5:   48 8d 35 00 00 00 00    lea    0x0(%rip),%rsi        # c <_start+0xc>
   c:   ba 09 00 00 00          mov    $0x9,%edx
  11:   b8 01 00 00 00          mov    $0x1,%eax
  16:   0f 05                   syscall
  18:   48 31 ff                xor    %rdi,%rdi
  1b:   b8 3c 00 00 00          mov    $0x3c,%eax
  20:   0f 05                   syscall
$ ld --dynamic-linker=/lib64/ld-linux-x86-64.so.2 -pie hello-pie.o -o hello-pie
$ objdump -d hello-pie

hello-pie:     file format elf64-x86-64


Disassembly of section .text:

0000000000000200 <_start>:
 200:   bf 01 00 00 00          mov    $0x1,%edi
 205:   48 8d 35 f4 0d 20 00    lea    0x200df4(%rip),%rsi        # 201000 <_GLOBAL_OFFSET_TABLE_>
 20c:   ba 09 00 00 00          mov    $0x9,%edx
 211:   b8 01 00 00 00          mov    $0x1,%eax
 216:   0f 05                   syscall
 218:   48 31 ff                xor    %rdi,%rdi
 21b:   b8 3c 00 00 00          mov    $0x3c,%eax
 220:   0f 05                   syscall
```

PIE(Position Independent code)的核心在于，使用 rip 寄存器来制造相对跳转，待链接时再使用真实的物理地址。
