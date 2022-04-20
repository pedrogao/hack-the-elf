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


