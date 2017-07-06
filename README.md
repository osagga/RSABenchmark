# RSA_Benchmark
Benchmarking two ways of doing RSA ecryption and Decryption

## How to use:
- [Visual Studio](https://www.visualstudio.com/):
	- Clone the repo then "open folder" and you should be able to compile
- [Mono Project](http://www.mono-project.com/):
	- Clone the repo then:
	`mcs -r:BouncyCastle.1.8.1/lib/BouncyCastle.Crypto.dll RSA_bench.cs && mono RSA_bench.exe`

