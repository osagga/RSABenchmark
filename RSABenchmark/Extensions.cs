using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;

namespace RSABenchmark
{
    public static class Extensions
    {
        /// <summary>
        /// Preforms RSA decryption (or signing) using private key.
        /// </summary>
        /// <param name="privKey">The private key</param>
        /// <param name="encrypted">Data to decrypt (or sign)</param>
        /// <returns></returns>
        internal static byte[] Decrypt(this RsaPrivateCrtKeyParameters privKey, byte[] encrypted)
        {
            if(encrypted == null)
                throw new ArgumentNullException(nameof(encrypted));

            RsaEngine engine = new RsaEngine();
            engine.Init(false, privKey);

            return engine.ProcessBlock(encrypted, 0, encrypted.Length);
        }

        /// <summary>
        /// Preforms RSA encryption using public key.
        /// </summary>
        /// <param name="pubKey">Public key</param>
        /// <param name="data">Data to encrypt</param>
        /// <returns></returns>
        internal static byte[] Encrypt(this RsaKeyParameters pubKey, byte[] data)
        {
            if(data == null)
                throw new ArgumentNullException(nameof(data));

            RsaEngine engine = new RsaEngine();
            engine.Init(true, pubKey);

            return engine.ProcessBlock(data, 0, data.Length);
        }

        internal static byte[] ToBytes(this RsaKeyParameters pubKey)
        {
            RsaPublicKeyStructure keyStruct = new RsaPublicKeyStructure(
                pubKey.Modulus,
                pubKey.Exponent);
            var privInfo = new PrivateKeyInfo(AlgID, keyStruct.ToAsn1Object());
            return privInfo.ToAsn1Object().GetEncoded();
        }

        public static byte[] GenEncryptableData(this RsaKeyParameters _key)
        {
            var Modulus = _key.Modulus;
            var KeySize = _key.Modulus.BitLength;
            SecureRandom random = new SecureRandom();

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

        internal static AlgorithmIdentifier AlgID = new AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.1.1"), DerNull.Instance);

        internal static RsaKeyParameters ToPublicKey(this RsaPrivateCrtKeyParameters s)
        {
            return new RsaKeyParameters(false, s.Modulus, s.PublicExponent);
        }
    }
}
