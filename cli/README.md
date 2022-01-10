# cli

## Getting started

```
$ cmake -S . -B build
$ cmake --build build

# Optionally, you can install the tool on your system:
$ cmake --install build
```

## Usage

```
usage: ./build/cli <command> <args>

You are probably interested in one of these commands:

manipulate RKFP images
    info <dump-file>               Display information about a given RKFP image
    extract_rkfp <dir>             Extract the content of a RKFP image. Multiple
                                   output files will be created.
    make_rkfp <dir>                Make a RKFP image. Output file: './image.bin'

manipulate kernel images and partitions
    extract_kernel <part-file>     Extract the kernel image inside a kernel partition.
                                   Output file: './kernel-extracted.bin'
```

## License

This `cli` tool is released under the GNU General Public License v2.0, see the
[LICENSE](./LICENSE.txt) file for more information.
