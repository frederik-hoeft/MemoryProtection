# MemoryProtection

| :exclamation:  Discontinuation notice   |
|-----------------------------------------|
This implementation is no longer under active development and has been succeeded by the [PrySec project](https://github.com/PrySec/PrySec), which serves as its spiritual successor.

---

A collection of anti debug methods and crypto algorithms using protected memory only. Intended for dealing with passwords and confidential data.

#### TODO: 
- [ ] documentation
- [x] support for Linux
   - [x] ~(currently broken)~ need to get page size dynamically [(Stackoverflow)](https://stackoverflow.com/questions/63871190/c-sharp-linux-getpagesize-returns-0)
- [x] support for OSX (experimental)
- [x] SHA-256 implementation using protected memory, zero-freeing used buffers.
- [x] Blake2b implementation using protected memory, zero-freeing used buffers.
- [x] Scrypt implementation using protected memory, zero-freeing used buffers.
- [x] AES-256 CBC implementation using protected memory, zero-freeing used buffers.

###### For now take a look at Program.cs for examples and usage :)
