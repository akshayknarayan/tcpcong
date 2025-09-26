# tcpcong

A KernelScript tracepoint program.

## Building

```bash
# Compile the KernelScript source
kernelscript compile tcpcong.ks

# Build the generated C code
cd tcpcong && make

# Run the program (requires root privileges)
cd tcpcong && make run
```

## Program Structure

- `tcpcong.ks` - Main KernelScript source file
- Generated files will be placed in `tcpcong/` directory after compilation

## Program Type: tracepoint

Tracepoint programs provide static tracing points in the kernel. This program traces the 'tcp/tcp_probe' tracepoint.
