/*
 * GOST2-128 Cipher
 * GOST2-128 by Alexander Pukall 2016
 * 
 * Based on the 25 Movember 1993 draft translation
 * by Aleksandr Malchik, with Whitfield Diffie, of the Government
 * Standard of the U.S.S.R. GOST 28149-89, "Cryptographic Transformation
 * Algorithm", effective 1 July 1990.  
 * 
 * 4096-bit keys with 64 * 64-bit subkeys
 * 
 * 128-bit block cipher (like AES) 64 rounds
 * 
 * Uses MD2II hash function to create the 64 subkeys
 * 
 * Code free for all, even for commercial software 
 * No restriction to use. Public Domain 
 *
 * Visual Studio 2012 
 */

using System;
using System.Text;

namespace Gost2_128_CS
{
    public class Gost2Hasher
    {
        private const int n1 = 512;
        int x1, x2, i;
        byte[] h2 = new byte[n1];
        byte[] h1 = new byte[n1 * 3];

        static readonly byte[] s4 = new byte[] {
           13,199,11,67,237,193,164,77,115,184,141,222,73,
           38,147,36,150,87,21,104,12,61,156,101,111,145,
           119,22,207,35,198,37,171,167,80,30,219,28,213,
           121,86,29,214,242,6,4,89,162,110,175,19,157,
           3,88,234,94,144,118,159,239,100,17,182,173,238,
           68,16,79,132,54,163,52,9,58,57,55,229,192,
           170,226,56,231,187,158,70,224,233,245,26,47,32,
           44,247,8,251,20,197,185,109,153,204,218,93,178,
           212,137,84,174,24,120,130,149,72,180,181,208,255,
           189,152,18,143,176,60,249,27,227,128,139,243,253,
           59,123,172,108,211,96,138,10,215,42,225,40,81,
           65,90,25,98,126,154,64,124,116,122,5,1,168,
           83,190,131,191,244,240,235,177,155,228,125,66,43,
           201,248,220,129,188,230,62,75,71,78,34,31,216,
           254,136,91,114,106,46,217,196,92,151,209,133,51,
           236,33,252,127,179,69,7,183,105,146,97,39,15,
           205,112,200,166,223,45,48,246,186,41,148,140,107,
           76,85,95,194,142,50,49,134,23,135,169,221,210,
           203,63,165,82,161,202,53,14,206,232,103,102,195,
           117,250,99,0,74,160,241,2,113
        };

        public Gost2Hasher() { init(); }

        private void init()
        {
            x1 = 0;
            x2 = 0;
            for (i = 0; i < n1; i++) h2[i] = 0;
            for (i = 0; i < n1 * 3; i++) h1[i] = 0;
        }

        public void hashing(byte[] t1, int b6)
        {
            int b1, b2, b3, b4, b5;
            b4 = 0;
            while (b6 > 0)
            {
                for (; b6 > 0 && x2 < n1; b6--, x2++)
                {
                    b5 = t1[b4++];
                    h1[x2 + n1] = (byte)b5;
                    h1[x2 + (n1 * 2)] = (byte)(b5 ^ h1[x2]);
                    byte idx = (byte)(b5 ^ x1);
                    h2[x2] = (byte)(h2[x2] ^ s4[idx]);
                    x1 = h2[x2];
                }
                if (x2 == n1)
                {
                    b2 = 0;
                    x2 = 0;
                    for (b3 = 0; b3 < (n1 + 2); b3++)
                    {
                        for (b1 = 0; b1 < (n1 * 3); b1++)
                            b2 = h1[b1] ^= s4[b2];
                        b2 = (b2 + b3) % 256;
                    }
                }
            }
        }

        public void end(byte[] h4)
        {
            byte[] h3 = new byte[n1];
            int n4 = n1 - x2;
            for (int i = 0; i < n4; i++) h3[i] = (byte)n4;
            hashing(h3, n4);
            hashing(h2, h2.Length);
            for (int i = 0; i < n1; i++) h4[i] = h1[i];
        }

        public void create_keys(byte[] h4, out ulong[] key)
        {
            key = new ulong[64];
            int k = 0;
            for (int i = 0; i < 64; i++)
            {
                key[i] = 0UL;
                for (int z = 0; z < 8; z++)
                    key[i] = unchecked((key[i] << 8) + (ulong)(h4[k++] & 0xff));
            }
        }
    }

    public class Gost2Cipher
    {
        static readonly byte[] k1 = { 0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3 };
        static readonly byte[] k2 = { 0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9 };
        static readonly byte[] k3 = { 0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB };
        static readonly byte[] k4 = { 0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3 };
        static readonly byte[] k5 = { 0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2 };
        static readonly byte[] k6 = { 0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE };
        static readonly byte[] k7 = { 0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC };
        static readonly byte[] k8 = { 0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC };

        static readonly byte[] k9 = { 0xC,0x4,0x6,0x2,0xA,0x5,0xB,0x9,0xE,0x8,0xD,0x7,0x0,0x3,0xF,0x1 };
        static readonly byte[] k10 = { 0x6,0x8,0x2,0x3,0x9,0xA,0x5,0xC,0x1,0xE,0x4,0x7,0xB,0xD,0x0,0xF };
        static readonly byte[] k11 = { 0xB,0x3,0x5,0x8,0x2,0xF,0xA,0xD,0xE,0x1,0x7,0x4,0xC,0x9,0x6,0x0 };
        static readonly byte[] k12 = { 0xC,0x8,0x2,0x1,0xD,0x4,0xF,0x6,0x7,0x0,0xA,0x5,0x3,0xE,0x9,0xB };
        static readonly byte[] k13 = { 0x7,0xF,0x5,0xA,0x8,0x1,0x6,0xD,0x0,0x9,0x3,0xE,0xB,0x4,0x2,0xC };
        static readonly byte[] k14 = { 0x5,0xD,0xF,0x6,0x9,0x2,0xC,0xA,0xB,0x7,0x8,0x1,0x4,0x3,0xE,0x0 };
        static readonly byte[] k15 = { 0x8,0xE,0x2,0x5,0x6,0x9,0x1,0xC,0xF,0x4,0xB,0x0,0xD,0xA,0x3,0x7 };
        static readonly byte[] k16 = { 0x1,0x7,0xE,0xD,0x0,0x5,0x8,0x3,0x4,0xF,0xA,0x6,0x9,0xC,0xB,0x2 };

        byte[] k175 = new byte[256];
        byte[] k153 = new byte[256];
        byte[] k131 = new byte[256];
        byte[] k109 = new byte[256];
        byte[] k87 = new byte[256];
        byte[] k65 = new byte[256];
        byte[] k43 = new byte[256];
        byte[] k21 = new byte[256];

        public Gost2Cipher() { kboxinit(); }

        public void kboxinit()
        {
            for (int i = 0; i < 256; i++)
            {
                k175[i] = (byte)((k16[i >> 4] << 4) | k15[i & 15]);
                k153[i] = (byte)((k14[i >> 4] << 4) | k13[i & 15]);
                k131[i] = (byte)((k12[i >> 4] << 4) | k11[i & 15]);
                k109[i] = (byte)((k10[i >> 4] << 4) | k9[i & 15]);
                k87[i] = (byte)((k8[i >> 4] << 4) | k7[i & 15]);
                k65[i] = (byte)((k6[i >> 4] << 4) | k5[i & 15]);
                k43[i] = (byte)((k4[i >> 4] << 4) | k3[i & 15]);
                k21[i] = (byte)((k2[i >> 4] << 4) | k1[i & 15]);
            }
        }

        static ulong RotateLeft11(ulong x)
        {
            return (x << 11) | (x >> (64 - 11));
        }

        ulong f(ulong x)
        {
            ulong y = x >> 32;
            ulong z = x & 0xffffffffUL;
            y = ((ulong)k87[(int)((y >> 24) & 255)] << 24) |
                ((ulong)k65[(int)((y >> 16) & 255)] << 16) |
                ((ulong)k43[(int)((y >> 8) & 255)] << 8) |
                ((ulong)k21[(int)(y & 255)]);
            z = ((ulong)k175[(int)((z >> 24) & 255)] << 24) |
                ((ulong)k153[(int)((z >> 16) & 255)] << 16) |
                ((ulong)k131[(int)((z >> 8) & 255)] << 8) |
                ((ulong)k109[(int)(z & 255)]);
            x = (y << 32) | (z & 0xffffffffUL);
            return RotateLeft11(x);
        }

        public void gostcrypt(ulong[] input, out ulong[] output, ulong[] key)
        {
            ulong ngost1 = input[0];
            ulong ngost2 = input[1];
            int k = 0;
            for (int i = 0; i < 32; i++)
            {
                ngost2 ^= f(ngost1 + key[k++]);
                ngost1 ^= f(ngost2 + key[k++]);
            }
            output = new ulong[] { ngost2, ngost1 };
        }

        public void gostdecrypt(ulong[] input, out ulong[] output, ulong[] key)
        {
            ulong ngost1 = input[0];
            ulong ngost2 = input[1];
            int k = 63;
            for (int i = 0; i < 32; i++)
            {
                ngost2 ^= f(ngost1 + key[k--]);
                ngost1 ^= f(ngost2 + key[k--]);
            }
            output = new ulong[] { ngost2, ngost1 };
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            Gost2Cipher cipher = new Gost2Cipher();
            Gost2Hasher hasher = new Gost2Hasher();

            byte[] text = new byte[33];
            ulong[] key;
            ulong[] plain = new ulong[2];
            byte[] h4 = new byte[512];

            Console.WriteLine("GOST2-128 by Alexander PUKALL 2016");
            Console.WriteLine("128-bit block, 4096-bit subkeys, 64 rounds");
            Console.WriteLine("Code can be freely used even for commercial software");
            Console.WriteLine("Based on GOST 28147-89 by Aleksandr Malchik with Whitfield Diffie\n");

            // === EXAMPLE 1 ===
            hasher = new Gost2Hasher();
            cipher = new Gost2Cipher();
            string key1 = "My secret password!0123456789abc";
            Encoding.ASCII.GetBytes(key1, 0, key1.Length, text, 0);
            hasher.hashing(text, 32);
            hasher.end(h4);
            hasher.create_keys(h4, out key);
            plain[0] = 0xFEFEFEFEFEFEFEFEUL;
            plain[1] = 0xFEFEFEFEFEFEFEFEUL;
            Console.WriteLine("Key 1:{0}", key1);
            Console.WriteLine("Plaintext  1: FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE");

            ulong[] cipher1;
            cipher.gostcrypt(plain, out cipher1, key);
            Console.WriteLine("Encryption 1: {0:X16}{1:X16}", cipher1[0], cipher1[1]);

            ulong[] dec1;
            cipher.gostdecrypt(cipher1, out dec1, key);
            Console.WriteLine("Decryption 1: {0:X16}{1:X16}\n", dec1[0], dec1[1]);

            // === EXAMPLE 2 ===
            hasher = new Gost2Hasher();
            cipher = new Gost2Cipher();
            string key2 = "My secret password!0123456789ABC";
            Encoding.ASCII.GetBytes(key2, 0, key2.Length, text, 0);
            hasher.hashing(text, 32);
            hasher.end(h4);
            hasher.create_keys(h4, out key);
            plain[0] = 0x0000000000000000UL;
            plain[1] = 0x0000000000000000UL;
            Console.WriteLine("Key 2:{0}", key2);
            Console.WriteLine("Plaintext  2: 00000000000000000000000000000000");

            ulong[] cipher2;
            cipher.gostcrypt(plain, out cipher2, key);
            Console.WriteLine("Encryption 2: {0:X16}{1:X16}", cipher2[0], cipher2[1]);

            ulong[] dec2;
            cipher.gostdecrypt(cipher2, out dec2, key);
            Console.WriteLine("Decryption 2: {0:X16}{1:X16}\n", dec2[0], dec2[1]);

            // === EXAMPLE 3 ===
            hasher = new Gost2Hasher();
            cipher = new Gost2Cipher();
            string key3 = "My secret password!0123456789abZ";
            Encoding.ASCII.GetBytes(key3, 0, key3.Length, text, 0);
            hasher.hashing(text, 32);
            hasher.end(h4);
            hasher.create_keys(h4, out key);
            plain[0] = 0x0000000000000000UL;
            plain[1] = 0x0000000000000001UL;
            Console.WriteLine("Key 3:{0}", key3);
            Console.WriteLine("Plaintext  3: 00000000000000000000000000000001");

            ulong[] cipher3;
            cipher.gostcrypt(plain, out cipher3, key);
            Console.WriteLine("Encryption 3: {0:X16}{1:X16}", cipher3[0], cipher3[1]);

            ulong[] dec3;
            cipher.gostdecrypt(cipher3, out dec3, key);
            Console.WriteLine("Decryption 3: {0:X16}{1:X16}\n", dec3[0], dec3[1]);
        }
    }
}

            /*
             
            Key 1:My secret password!0123456789abc
            Plaintext  1: FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE
            Encryption 1: 8CA4C196B773D9C9A00AD3931F9B2B09
            Decryption 1: FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE

            Key 2:My secret password!0123456789ABC
            Plaintext  2: 00000000000000000000000000000000
            Encryption 2: 96AB544910861D5B22B04FC984D80098
            Decryption 2: 00000000000000000000000000000000

            Key 3:My secret password!0123456789abZ
            Plaintext  3: 00000000000000000000000000000001
            Encryption 3: ACF914AC22AE2079390BC240ED51916F
            Decryption 3: 00000000000000000000000000000001

            */
