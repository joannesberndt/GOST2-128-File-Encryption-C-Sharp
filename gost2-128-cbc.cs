
/* 
 * GOST2-128 File Encryptor/Decryptor (CBC + SHA-256 authentication)
 * Single-file utility: includes GOST2-128 (Pukall), SHA-256, CBC, IV generation, and I/O.
 *
 * Build:
 *   Visual Studio 2012
 *
 * Usage:
 *   gost2-128-cbc c <input_file>   -> produces <input_file>.gost2
 *   gost2-128-cbc d <input_file>   -> removes .gost2 suffix if present, else appends .dec
 *
 * File format (encrypted):
 *   [16 bytes IV (clear)] [ciphertext (PKCS#7 padded)] [32 bytes SHA-256 over ciphertext only]
 *
 * Password:
 *   Asked interactively (not via CLI). Not echoed on screen.
 *
 *
 * Randomness:
 *   Uses System.Security.Cryptography.RandomNumberGenerator
 */

using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace Gost2_128_CBC_File
{
    public class Gost2Hasher
    {
        private const int n1 = 512;
        int x1, x2, i_g;
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
            for (i_g = 0; i_g < n1; i_g++) h2[i_g] = 0;
            for (i_g = 0; i_g < n1 * 3; i_g++) h1[i_g] = 0;
        }

        public void hashing(byte[] t1, int b6)
        {
            int b1,b2,b3,b4,b5;
            b4 = 0;
            while (b6 > 0) {
                for (; b6 > 0 && x2 < n1; b6--, x2++) {
                    b5 = t1[b4++];
                    h1[x2 + n1] = (byte)b5;
                    h1[x2 + (n1*2)] = (byte)(b5 ^ h1[x2]);
                    byte idx = (byte)(b5 ^ x1);
                    h2[x2] = (byte)(h2[x2] ^ s4[idx]);
                    x1 = h2[x2];
                }
                if (x2 == n1)
                {
                    b2 = 0;
                    x2 = 0;
                    for (b3 = 0; b3 < (n1+2); b3++) {
                        for (b1 = 0; b1 < (n1*3); b1++)
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
            for (int j = 0; j < n4; j++) h3[j] = (byte)n4;
            hashing(h3, n4);
            hashing(h2, h2.Length);
            for (int j = 0; j < n1; j++) h4[j] = h1[j];
        }

        public void create_keys(byte[] h4, out ulong[] key)
        {
            key = new ulong[64];
            int k=0;
            for (int i=0;i<64;i++) {
                ulong acc = 0UL;
                for (int z=0;z<8;z++) {
                    acc = (acc << 8) + (ulong)(h4[k++] & 0xff);
                }
                key[i] = acc;
            }
        }
    }

    public class Gost2Cipher
    {
        static readonly byte[] k1 = {0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3};
        static readonly byte[] k2 = {0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9};
        static readonly byte[] k3 = {0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB};
        static readonly byte[] k4 = {0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3};
        static readonly byte[] k5 = {0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2};
        static readonly byte[] k6 = {0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE};
        static readonly byte[] k7 = {0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC};
        static readonly byte[] k8 = {0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC};

        static readonly byte[] k9  = {0xC,0x4,0x6,0x2,0xA,0x5,0xB,0x9,0xE,0x8,0xD,0x7,0x0,0x3,0xF,0x1};
        static readonly byte[] k10 = {0x6,0x8,0x2,0x3,0x9,0xA,0x5,0xC,0x1,0xE,0x4,0x7,0xB,0xD,0x0,0xF};
        static readonly byte[] k11 = {0xB,0x3,0x5,0x8,0x2,0xF,0xA,0xD,0xE,0x1,0x7,0x4,0xC,0x9,0x6,0x0};
        static readonly byte[] k12 = {0xC,0x8,0x2,0x1,0xD,0x4,0xF,0x6,0x7,0x0,0xA,0x5,0x3,0xE,0x9,0xB};
        static readonly byte[] k13 = {0x7,0xF,0x5,0xA,0x8,0x1,0x6,0xD,0x0,0x9,0x3,0xE,0xB,0x4,0x2,0xC};
        static readonly byte[] k14 = {0x5,0xD,0xF,0x6,0x9,0x2,0xC,0xA,0xB,0x7,0x8,0x1,0x4,0x3,0xE,0x0};
        static readonly byte[] k15 = {0x8,0xE,0x2,0x5,0x6,0x9,0x1,0xC,0xF,0x4,0xB,0x0,0xD,0xA,0x3,0x7};
        static readonly byte[] k16 = {0x1,0x7,0xE,0xD,0x0,0x5,0x8,0x3,0x4,0xF,0xA,0x6,0x9,0xC,0xB,0x2};

        byte[] k175 = new byte[256], k153 = new byte[256], k131 = new byte[256], k109 = new byte[256];
        byte[] k87 = new byte[256], k65 = new byte[256], k43 = new byte[256], k21 = new byte[256];

        public Gost2Cipher() { kboxinit(); }

        public void kboxinit()
        {
            for (int i=0;i<256;i++) {
                k175[i] = (byte)((k16[i >> 4] << 4) | k15[i & 15]);
                k153[i] = (byte)((k14[i >> 4] << 4) | k13[i & 15]);
                k131[i] = (byte)((k12[i >> 4] << 4) | k11[i & 15]);
                k109[i] = (byte)((k10[i >> 4] << 4) | k9[i & 15]);
                k87[i]  = (byte)((k8[i >> 4]  << 4) | k7[i & 15]);
                k65[i]  = (byte)((k6[i >> 4]  << 4) | k5[i & 15]);
                k43[i]  = (byte)((k4[i >> 4]  << 4) | k3[i & 15]);
                k21[i]  = (byte)((k2[i >> 4]  << 4) | k1[i & 15]);
            }
        }

        static UInt64 RotateLeft11(UInt64 x) { return (x << 11) | (x >> (64 - 11)); }

        UInt64 f(UInt64 x)
        {
            UInt64 y = x >> 32;
            UInt64 z = x & 0xffffffffUL;

            y = ((UInt64)k87[(int)((y >> 24) & 255)] << 24) | ((UInt64)k65[(int)((y >> 16) & 255)] << 16) |
                ((UInt64)k43[(int)((y >> 8) & 255)] << 8) | ((UInt64)k21[(int)(y & 255)]);
            z = ((UInt64)k175[(int)((z >> 24) & 255)] << 24) | ((UInt64)k153[(int)((z >> 16) & 255)] << 16) |
                ((UInt64)k131[(int)((z >> 8) & 255)] << 8) | ((UInt64)k109[(int)(z & 255)]);
            x = (y << 32) | (z & 0xffffffffUL);
            return RotateLeft11(x);
        }

        public void gostcrypt(UInt64[] input, out UInt64[] output, UInt64[] key)
        {
            UInt64 a = input[0], b = input[1];
            int k = 0;
            for (int i=0;i<32;i++){
                b ^= f(a + key[k++]);
                a ^= f(b + key[k++]);
            }
            output = new UInt64[] { b, a };
        }

        public void gostdecrypt(UInt64[] input, out UInt64[] output, UInt64[] key)
        {
            UInt64 a = input[0], b = input[1];
            int k = 63;
            for (int i=0;i<32;i++){
                b ^= f(a + key[k--]);
                a ^= f(b + key[k--]);
            }
            output = new UInt64[] { b, a };
        }
    }

    class Program
    {
        const int BLOCK_SIZE = 16;
        const int READ_CHUNK = 64 * 1024;

        static void PromptPassword(StringBuilder sb, string prompt)
        {
            Console.Write(prompt);
            while (true)
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (sb.Length > 0) sb.Length--;
                    continue;
                }
                sb.Append(key.KeyChar);
            }
            Console.WriteLine();
        }

        static void GenerateIV(byte[] iv)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }
        }

        static void MakeOutputNameEncrypt(string inPath, out string outPath)
        {
            outPath = inPath + ".gost2";
        }

        static void MakeOutputNameDecrypt(string inPath, out string outPath)
        {
            if (inPath.EndsWith(".gost2", StringComparison.OrdinalIgnoreCase))
                outPath = inPath.Substring(0, inPath.Length - 6);
            else
                outPath = inPath + ".dec";
        }

        static void BeBytesToWords(byte[] input, int offset, out UInt64 a, out UInt64 b)
        {
            a = 0; b = 0;
            for (int i = 0; i < 8; i++) a = (a << 8) | input[offset + i];
            for (int i = 0; i < 8; i++) b = (b << 8) | input[offset + 8 + i];
        }

        static void BeWordsToBytes(UInt64 a, UInt64 b, byte[] outbuf, int offset)
        {
            for (int i = 7; i >= 0; i--) outbuf[offset + (7 - i)] = (byte)((a >> (i * 8)) & 0xFF);
            for (int i = 7; i >= 0; i--) outbuf[offset + 8 + (7 - i)] = (byte)((b >> (i * 8)) & 0xFF);
        }

        static int Pkcs7Unpad(byte[] buf, ref int len)
        {
            if (len == 0 || (len % BLOCK_SIZE) != 0) return 0;
            byte pad = buf[len - 1];
            if (pad == 0 || pad > BLOCK_SIZE) return 0;
            for (int i = 0; i < pad; i++)
            {
                if (buf[len - 1 - i] != pad) return 0;
            }
            len -= pad;
            return 1;
        }

        static int Pkcs7Pad(byte[] buf, int used, int cap)
        {
            int pad = BLOCK_SIZE - (used % BLOCK_SIZE);
            if (used + pad > cap) return 0;
            for (int i = 0; i < pad; i++) buf[used + i] = (byte)pad;
            return used + pad;
        }

        static void DeriveGostSubkeysFromPassword(string password, out UInt64[] subkeys)
        {
            Gost2Hasher hasher = new Gost2Hasher();
            byte[] pw = Encoding.UTF8.GetBytes(password);
            hasher.hashing(pw, pw.Length);
            byte[] h4 = new byte[512];
            hasher.end(h4);
            ulong[] tmpKeys;
            hasher.create_keys(h4, out tmpKeys);
            subkeys = new UInt64[64];
            for (int i = 0; i < 64; i++) subkeys[i] = (UInt64)tmpKeys[i];
            Array.Clear(pw, 0, pw.Length);
        }

        static void CbcEncryptStream(FileStream fin, FileStream fout, UInt64[] subkeys, byte[] iv, out byte[] out_hash)
        {
            // Write IV first
            fout.Write(iv, 0, BLOCK_SIZE);

            byte[] inbuf = new byte[READ_CHUNK + BLOCK_SIZE];
            byte[] outbuf = new byte[READ_CHUNK + BLOCK_SIZE];
            byte[] prev = new byte[BLOCK_SIZE];
            Array.Copy(iv, prev, BLOCK_SIZE);

            SHA256 sha = SHA256.Create();

            try
            {
                int r;
                while (true)
                {
                    r = fin.Read(inbuf, 0, READ_CHUNK);
                    if (r < READ_CHUNK)
                    {
                        // final read: pad
                        int total = Pkcs7Pad(inbuf, r, inbuf.Length);
                        if (total == 0) throw new Exception("Not enough space for padding");

                        for (int off = 0; off < total; off += BLOCK_SIZE)
                        {
                            for (int i = 0; i < BLOCK_SIZE; i++) inbuf[off + i] ^= prev[i];
                            UInt64 a, b;
                            BeBytesToWords(inbuf, off, out a, out b);
                            Gost2Cipher cipher = new Gost2Cipher();
                            UInt64[] outw;
                            cipher.gostcrypt(new UInt64[] { a, b }, out outw, subkeys);
                            BeWordsToBytes(outw[0], outw[1], outbuf, off);
                            Array.Copy(outbuf, off, prev, 0, BLOCK_SIZE);
                        }
                        fout.Write(outbuf, 0, total);
                        sha.TransformBlock(outbuf, 0, total, outbuf, 0);
                        break;
                    }
                    else
                    {
                        int full = (r / BLOCK_SIZE) * BLOCK_SIZE;
                        int rem = r - full;

                        for (int off = 0; off < full; off += BLOCK_SIZE)
                        {
                            for (int i = 0; i < BLOCK_SIZE; i++) inbuf[off + i] ^= prev[i];
                            UInt64 a, b;
                            BeBytesToWords(inbuf, off, out a, out b);
                            Gost2Cipher cipher = new Gost2Cipher();
                            UInt64[] outw;
                            cipher.gostcrypt(new UInt64[] { a, b }, out outw, subkeys);
                            BeWordsToBytes(outw[0], outw[1], outbuf, off);
                            Array.Copy(outbuf, off, prev, 0, BLOCK_SIZE);
                        }
                        if (full > 0)
                        {
                            fout.Write(outbuf, 0, full);
                            sha.TransformBlock(outbuf, 0, full, outbuf, 0);
                        }

                        if (rem > 0)
                        {
                            Array.Copy(inbuf, full, inbuf, 0, rem);
                            int got = fin.Read(inbuf, rem, READ_CHUNK - rem);
                            int r2 = rem + got;
                            int full2 = (r2 / BLOCK_SIZE) * BLOCK_SIZE;
                            int rem2 = r2 - full2;

                            for (int off = 0; off < full2; off += BLOCK_SIZE)
                            {
                                for (int i = 0; i < BLOCK_SIZE; i++) inbuf[off + i] ^= prev[i];
                                UInt64 a, b;
                                BeBytesToWords(inbuf, off, out a, out b);
                                Gost2Cipher cipher = new Gost2Cipher();
                                UInt64[] outw;
                                cipher.gostcrypt(new UInt64[] { a, b }, out outw, subkeys);
                                BeWordsToBytes(outw[0], outw[1], outbuf, off);
                                Array.Copy(outbuf, off, prev, 0, BLOCK_SIZE);
                            }
                            if (full2 > 0)
                            {
                                fout.Write(outbuf, 0, full2);
                                sha.TransformBlock(outbuf, 0, full2, outbuf, 0);
                            }
                            if (rem2 > 0) Array.Copy(inbuf, full2, inbuf, 0, rem2);
                            int total = Pkcs7Pad(inbuf, rem2, inbuf.Length);
                            if (total == 0) throw new Exception("Not enough space for padding");
                            for (int off = 0; off < total; off += BLOCK_SIZE)
                            {
                                for (int i = 0; i < BLOCK_SIZE; i++) inbuf[off + i] ^= prev[i];
                                UInt64 a, b;
                                BeBytesToWords(inbuf, off, out a, out b);
                                Gost2Cipher cipher = new Gost2Cipher();
                                UInt64[] outw;
                                cipher.gostcrypt(new UInt64[] { a, b }, out outw, subkeys);
                                BeWordsToBytes(outw[0], outw[1], outbuf, off);
                                Array.Copy(outbuf, off, prev, 0, BLOCK_SIZE);
                            }
                            fout.Write(outbuf, 0, total);
                            sha.TransformBlock(outbuf, 0, total, outbuf, 0);
                            break;
                        }
                    }
                }

                sha.TransformFinalBlock(new byte[0], 0, 0);
                out_hash = sha.Hash;
                fout.Write(out_hash, 0, out_hash.Length);
            }
            finally
            {
                sha.Clear();
            }
        }

        static bool ByteArrayEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        static void CbcDecryptStream(FileStream fin, FileStream fout, UInt64[] subkeys, out bool auth_ok)
        {
            auth_ok = false;
            if (!fin.CanSeek) throw new Exception("Input stream must be seekable");

            long fsz = fin.Length;
            if (fsz < BLOCK_SIZE + 32) throw new Exception("Error: input too small.");
            long payload = fsz - 32;

            fin.Seek(0, SeekOrigin.Begin);
            byte[] iv = new byte[BLOCK_SIZE];
            if (fin.Read(iv, 0, BLOCK_SIZE) != BLOCK_SIZE) throw new Exception("Cannot read IV");

            fin.Seek(payload, SeekOrigin.Begin);
            byte[] stored_hash = new byte[32];
            if (fin.Read(stored_hash, 0, 32) != 32) throw new Exception("Cannot read stored hash");

            fin.Seek(BLOCK_SIZE, SeekOrigin.Begin);
            long remaining = payload - BLOCK_SIZE;
            if (remaining <= 0 || (remaining % BLOCK_SIZE) != 0) throw new Exception("Error: invalid ciphertext size.");

            byte[] prev = new byte[BLOCK_SIZE];
            Array.Copy(iv, prev, BLOCK_SIZE);
            byte[] inbuf = new byte[READ_CHUNK];
            byte[] outbuf = new byte[READ_CHUNK];

            SHA256 sha = SHA256.Create();
            try
            {
                while (remaining > 0)
                {
                    int toread = remaining > READ_CHUNK ? READ_CHUNK : (int)remaining;
                    if ((toread % BLOCK_SIZE) != 0) toread -= (toread % BLOCK_SIZE);
                    int r = fin.Read(inbuf, 0, toread);
                    if (r != toread) throw new Exception("Read error");

                    sha.TransformBlock(inbuf, 0, r, inbuf, 0);

                    for (int off = 0; off < r; off += BLOCK_SIZE)
                    {
                        byte[] cpy = new byte[BLOCK_SIZE];
                        Array.Copy(inbuf, off, cpy, 0, BLOCK_SIZE);
                        UInt64 a, b;
                        BeBytesToWords(inbuf, off, out a, out b);
                        Gost2Cipher cipher = new Gost2Cipher();
                        UInt64[] outw;
                        cipher.gostdecrypt(new UInt64[] { a, b }, out outw, subkeys);
                        BeWordsToBytes(outw[0], outw[1], outbuf, off);
                        for (int i = 0; i < BLOCK_SIZE; i++) outbuf[off + i] ^= prev[i];
                        Array.Copy(cpy, 0, prev, 0, BLOCK_SIZE);
                    }

                    remaining -= r;
                    if (remaining > 0)
                    {
                        fout.Write(outbuf, 0, r);
                    }
                    else
                    {
                        if (r < BLOCK_SIZE) throw new Exception("Unexpected short block");
                        int keep = r - BLOCK_SIZE;
                        if (keep > 0) fout.Write(outbuf, 0, keep);
                        byte[] lastblk = new byte[BLOCK_SIZE];
                        Array.Copy(outbuf, keep, lastblk, 0, BLOCK_SIZE);
                        int lastlen = BLOCK_SIZE;
                        if (Pkcs7Unpad(lastblk, ref lastlen) == 0) throw new Exception("Error: invalid padding.");
                        if (lastlen > 0) fout.Write(lastblk, 0, lastlen);
                    }
                }

                sha.TransformFinalBlock(new byte[0], 0, 0);
                byte[] calc_hash = sha.Hash;
                auth_ok = ByteArrayEquals(calc_hash, stored_hash);
            }
            finally
            {
                sha.Clear();
            }
        }

        static int Main(string[] args)
        {
            if (args.Length != 2) { Console.Error.WriteLine("Usage: gost2-128-cbc c|d <input_file>"); return 1; }
            bool mode_encrypt = false, mode_decrypt = false;
            if (args[0] == "c") mode_encrypt = true;
            else if (args[0] == "d") mode_decrypt = true;
            else { Console.Error.WriteLine("Usage: gost2-128-cbc c|d <input_file>"); return 1; }

            string inpath = args[1];
            string outpath;
            if (mode_encrypt) outpath = inpath + ".gost2";
            else {
                if (inpath.EndsWith(".gost2", StringComparison.OrdinalIgnoreCase))
                    outpath = inpath.Substring(0, inpath.Length - 6);
                else outpath = inpath + ".dec";
            }

            if (!File.Exists(inpath)) { Console.Error.WriteLine("Error: cannot open input '" + inpath + "'"); return 1; }

            try
            {
                using (FileStream fin = new FileStream(inpath, FileMode.Open, FileAccess.Read))
                using (FileStream fout = new FileStream(outpath, FileMode.Create, FileAccess.Write))
                {
                    StringBuilder pw = new StringBuilder();
                    PromptPassword(pw, "Enter password: ");
                    string password = pw.ToString();

                    UInt64[] subkeys;
                    DeriveGostSubkeysFromPassword(password, out subkeys);

                    // Clear password
                    pw.Length = 0;
                    password = null;

                    if (mode_encrypt)
                    {
                        byte[] iv = new byte[BLOCK_SIZE];
                        GenerateIV(iv);
                        byte[] hash_out;
                        CbcEncryptStream(fin, fout, subkeys, iv, out hash_out);
                        Console.WriteLine("Encryption completed. Output: " + outpath);
                    }
                    else
                    {
                        bool auth_ok;
                        CbcDecryptStream(fin, fout, subkeys, out auth_ok);
                        Console.WriteLine("Decryption completed. Output: " + outpath);
                        Console.WriteLine("Authentication " + (auth_ok ? "OK" : "FAILED"));
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Operation failed: " + ex.Message);
                try { if (File.Exists(outpath)) File.Delete(outpath); } catch { }
                return 2;
            }
            return 0;
        }
    }
}
