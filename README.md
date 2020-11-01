# Packer SIGSEGV
This is an ELF packer that ciphers the process memory and deciphers it on
demand.  One page at a time. It does so by removing any access rights on the
pages and then handles the SIGSEGV signal to decipher the memory page and
restore its access. Reciphering and removing the access to an older page if
needed. This means that the whole process is never entierly deciphered in
memory.

# Usage
To pack /bin/echo use the following commands.

    cp /bin/echo .
    make -j echo.packed

# Limitations and possible improvements
This packer is just a proof of concept and has many limitations.

- It currently only support 64 bits relocatable ELF binaries.
- The cipher used is only a binary `not` on the bytes.
- Does not cipher the memory allocated by the process itself through `mmap`,
`sbrk` or anything else.
- A process calling `mprotect` might find its changes reverted by the packer or
might access a ciphered page without triggering the SIGSEGV.
- A process with a handler on SIGSEGV would likely prevent the packer's handler
to run.
  - As a result, a program cannot be packed twice.
- The runtime is pretty large while very little code is actually used during the
run time.
- It does not attempt to clean up the memory before starting the process,
especially the stack.

# Architecture details
## Helper programs
### loader
The `loader` program just loads an ELF, cipher its memory pages and run it. It's
just a simple program to help make sure most of the runtime works properly.

### encrypter
The `encrypter` program takes an ELF and cipher the content that will be loaded
at run time. Since the ciphering is done on a page basis, we have to make sure
that the in-file representation of the memory pages do not overlap. They
usually do overlap, that's why the ELF has to be padded before.

### elfpadder
The `elfpadder` program takes an ELF and check that the memory pages of the
loaded segments do not overlap in the file. If they do, it adds some padding
pages to separate them and correct the ELF data structures accordingly.
