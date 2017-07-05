using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Engines;
using System;
using System.Diagnostics;

namespace RSA_Benchmark
{
    public class RSA_Benchmark
    {
        private readonly static SecureRandom random = new SecureRandom();

        public static void testKey(int Exp, double iterations, double subIterations)
        {
            // Generate a list of 'iterations' keys.
            AsymmetricCipherKeyPair[] keys = genRandKeys( (int) iterations, BigInteger.ValueOf(Exp));
            // Generate a list of 'iterations' inputs.
            byte[][] data = genRandData(keys);

            // Normal RSA
            double EncTime = 0.0;
            double DecTime = 0.0;

            for (int i = 0; i < iterations; i++)
            {
                // Test key 'i' with input 'i' 'subIterations' times.
                var output = testData(keys[i], data[i], subIterations);
                EncTime += output[0];
                DecTime += output[1];

            }
            Console.WriteLine("Normal RSA |Encryption |e = {0} | {1} seconds", Exp, EncTime / iterations);
            Console.WriteLine("Normal RSA |Decryption |e = {0} | {1} seconds", Exp, DecTime / iterations);

            // Weird RSA

            for (int i = 0; i < iterations; i++)
            {
                // Extract the private key 'i' from the keypair 'i'
                var key = ((RsaPrivateCrtKeyParameters) keys[i].Private);
                BigInteger N = key.Modulus;
                // Generate a new private key with e = e * N
                keys[i] = GeneratePrivate(key.P, key.Q, N.Multiply(key.PublicExponent));
            }

            EncTime = 0.0;
            DecTime = 0.0;

            for (int i = 0; i < iterations; i++)
            {
                // Test key 'i' with input 'i' 'subIterations' times.
                var output = testData(keys[i], data[i], subIterations);
                EncTime += output[0];
                DecTime += output[1];

            }

            Console.WriteLine("Weird RSA |Encryption |e = {0} | {1} seconds", Exp, EncTime / iterations);
            Console.WriteLine("Weird RSA |Decryption |e = {0} | {1} seconds", Exp, DecTime / iterations);

            return;
        }

        public static double[] testData(AsymmetricCipherKeyPair key, byte[] input, double iterations)
        {
            Stopwatch sw = new Stopwatch();

            // Encrypt
            byte[] cipherText = Encrypt(key, input);
            // Decrypt
            byte[] plainText = Decrypt(key, cipherText);
            // Validate
            if (!new BigInteger(1,plainText).Equals(new BigInteger(1,input)))
                throw new InvalidCipherTextException("Validation Failed");

            // Benchmarks

            // Encryption
            sw.Start();

            for (int i = 0; i < iterations; i++)
                Encrypt(key, input);

            sw.Stop();

            double EncTime = sw.Elapsed.TotalSeconds / iterations;
            sw.Reset();

            // Decryption
            sw.Start();

            for (int i = 0; i < iterations; i++)
                Decrypt(key, cipherText);

            sw.Stop();

            double DecTime = sw.Elapsed.TotalSeconds / iterations;
            sw.Reset();

            return new double[] { EncTime, DecTime };
        }

        public static AsymmetricCipherKeyPair[] genRandKeys(int count, BigInteger e)
        {
            AsymmetricCipherKeyPair[] keys = new AsymmetricCipherKeyPair[count];

            for (int i = 0; i < count; i++)
                keys[i] = genKey(e);

            return keys;
        }

        public static byte[][] genRandData(AsymmetricCipherKeyPair[] keys)
        {
            var count = keys.Length;
            byte[][] data = new byte[count][];

            for (int i = 0; i < count; i++)
                data[i] = GenEncryptableData(keys[i]);

            return data;
        }

        public static  byte[] Decrypt(AsymmetricCipherKeyPair key, byte[] encrypted)
        {
            RsaPrivateCrtKeyParameters _Key = (RsaPrivateCrtKeyParameters) key.Private;

            if (encrypted == null)
                throw new ArgumentNullException(nameof(encrypted));

            RsaEngine engine = new RsaEngine();
            engine.Init(false, _Key);

            return engine.ProcessBlock(encrypted, 0, encrypted.Length);
        }

        public static byte[] Encrypt(AsymmetricCipherKeyPair key, byte[] data)
        {
            RsaKeyParameters _Key = (RsaKeyParameters) key.Public;

            if (data == null)
                throw new ArgumentNullException(nameof(data));

            RsaEngine engine = new RsaEngine();
            engine.Init(true, _Key);

            return engine.ProcessBlock(data, 0, data.Length);
        }

        public static AsymmetricCipherKeyPair genKey(BigInteger Exp, int KeySize = 2048)
        {
            var gen = new RsaKeyPairGenerator();
            gen.Init(new RsaKeyGenerationParameters(Exp, random, KeySize, 2)); // See A.15.2 IEEE P1363 v2 D1 for certainty parameter
            var pair = gen.GenerateKeyPair();
            return pair;
        }

        public static AsymmetricCipherKeyPair GeneratePrivate(BigInteger p, BigInteger q, BigInteger e)
        {
            BigInteger n, d, pSub1, qSub1, phi;

            n = p.Multiply(q);

            pSub1 = p.Subtract(BigInteger.One);
            qSub1 = q.Subtract(BigInteger.One);
            phi = pSub1.Multiply(qSub1);

            //
            // calculate the private exponent
            //

            d = e.ModInverse(phi);

            //
            // calculate the CRT factors
            //
            BigInteger dP, dQ, qInv;

            dP = d.Remainder(pSub1);
            dQ = d.Remainder(qSub1);
            qInv = q.ModInverse(p);

            return new AsymmetricCipherKeyPair(
                new RsaKeyParameters(false, n, e),
                new RsaPrivateCrtKeyParameters(n, e, d, p, q, dP, dQ, qInv));

        }

        public static byte[] GenEncryptableData(AsymmetricCipherKeyPair key)
        {
            var _key = (RsaKeyParameters)key.Public;
            var Modulus = _key.Modulus;
            var KeySize = _key.Modulus.BitLength;

            while (true)
            {
                byte[] bytes = new byte[KeySize / 8];
                random.NextBytes(bytes);
                BigInteger input = new BigInteger(1, bytes);

                if (input.CompareTo(Modulus) >= 0)
                    continue;

                return bytes;
            }
        }

        static void Main(string[] args)
        {
            // Number of (key, input) pairs
            double iterations = 10.0;
            // Number of iterations per pair
            double subIterations = 100.0;

            // Test e = 3
            testKey(3, iterations, subIterations);

            // Test e = 65537
            testKey(65537, iterations, subIterations);

            Console.WriteLine("------- Done --------");
            Console.ReadLine();
        }

    }

}
