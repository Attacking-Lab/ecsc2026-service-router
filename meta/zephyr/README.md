To set up the build, run

```sh
west init --local app
```

And install the toolchain (adjust the install path `-b` to you linking)
```sh
west sdk install -b ~/.local/zephyr/ -t xtensa-dc233c_zephyr-elf
```

To update dependencies/Zephyr

```sh
west update --narrow --fetch-opt=--depth=1
```

To build, run

```sh
west build -b qemu_xtensa/dc233c/mmu app
```

To (build and) run the system, run

```sh
west build -t run-virt
```

(**not** `west build -t run`, that will use the wrong board, and I want control over the QEMU command line)

To run self-tests instead, use
```sh
west build -t run-virt --extra-conf test.conf
```
