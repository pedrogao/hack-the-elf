# hack the elf

> Deep dive into ELF files
> 深入探索 ELF 文件

```sh
# in `~/.gdbinit`

# those are from earlier - if you didn't have these,
# now's your chance
set history save on
set disassembly-flavor intel

# this is the important bit:
source ~/ftl/elk/gdb-elk.py
```

## references

- https://fasterthanli.me/series/making-our-own-executable-packer
