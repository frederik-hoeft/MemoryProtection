# MemoryProtection
A collection of anti debug methods and crypto algorithms using protected memory only. Intended for dealing with passwords and confidential data.

#### TODO: 
- [ ] documentation
- [x] support for Linux
   - [ ] (currently broken) need to get page size dynamically [Stackoverflow](https://stackoverflow.com/questions/63871190/c-sharp-linux-getpagesize-returns-0)
- [ ] support for OSX
- [x] SHA-256 implementation using protected memory, zero-freeing used buffers.
- [x] Blake2b implementation using protected memory, zero-freeing used buffers.
- [x] Scrypt implementation using protected memory, zero-freeing used buffers.
- [ ] AES-256 (CBC or CFB) implementation using protected memory, zero-freeing used buffers.

###### For now take a look at Program.cs for examples and usage :)
