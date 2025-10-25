
/*
 * GOST2-128 + GCM file encrypt/decrypt tool (streaming, block by block)
 *
 * Usage:
 *   gost2-128-gcm c <input_file>   // encrypt -> writes <input_file>.gost2
 *   gost2-128-gcm d <input_file>   // decrypt -> strips .gost2 if present else adds .dec
 *
 * Password is requested interactively (not on the command line) with echo off.
 *
 * Output file (encryption): [IV(16 bytes)][CIPHERTEXT][TAG(16 bytes)]
 * Output file (decryption): plaintext is written block-by-block; at the end we print
 *                           whether authentication tag is OK or FAILED.
 *
 * GCM is implemented per NIST SP 800-38D:
 *   - H = E_K(0^128)
 *   - If IV length == 12, J0 = IV || 0x00000001
 *     else J0 = GHASH_H(IV || pad || 0^64 || [len(IV) in bits]_64)
 *   - CTR starts from inc32(J0) for data blocks
 *   - Tag T = E_K(J0) XOR GHASH_H(A||C||len(A)||len(C)), with AAD empty here
 *
 * Randomness is provided by System.Security.Cryptography.RandomNumberGenerator.
 *
 * NOTE: For decryption we stream plaintext out before tag verification
 *       This is NOT ideal for AEAD, but matches the behavior of the original C program.
 *
 * Visual Studio 2012
 */

using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace Gost2_128_GCM
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
    // --- END: GOST2-128 implementation ---

    // --- BEGIN: GCM and file wrapper ---
    public struct Be128
    {
        public ulong Hi;
        public ulong Lo;
    }

    public static class GcmGost2
    {
        // Buffer chunk for streaming
        private const int BUF_CHUNK = 4096;
        // Use the cipher and hasher
        private static Gost2Cipher cipher = new Gost2Cipher();
        private static Gost2Hasher hasher = new Gost2Hasher();

        // Compute H = E_K(0^128)
        public static void ComputeH(byte[] H, ulong[] key)
        {
            byte[] zero = new byte[16];
            GostEncryptBlock(zero, H, key);
        }

        // Big-endian 128-bit load/store
        public static Be128 LoadBE128(byte[] b, int offset)
        {
            Be128 x;
            x.Hi = ((ulong)b[offset + 0] << 56) | ((ulong)b[offset + 1] << 48) | ((ulong)b[offset + 2] << 40) | ((ulong)b[offset + 3] << 32) |
                   ((ulong)b[offset + 4] << 24) | ((ulong)b[offset + 5] << 16) | ((ulong)b[offset + 6] << 8) | ((ulong)b[offset + 7]);
            x.Lo = ((ulong)b[offset + 8] << 56) | ((ulong)b[offset + 9] << 48) | ((ulong)b[offset +10] << 40) | ((ulong)b[offset +11] << 32) |
                   ((ulong)b[offset +12] << 24) | ((ulong)b[offset +13] << 16) | ((ulong)b[offset +14] << 8) | ((ulong)b[offset +15]);
            return x;
        }

        public static void StoreBE128(Be128 x, byte[] b, int offset)
        {
            b[offset + 0] = (byte)(x.Hi >> 56); b[offset + 1] = (byte)(x.Hi >> 48);
            b[offset + 2] = (byte)(x.Hi >> 40); b[offset + 3] = (byte)(x.Hi >> 32);
            b[offset + 4] = (byte)(x.Hi >> 24); b[offset + 5] = (byte)(x.Hi >> 16);
            b[offset + 6] = (byte)(x.Hi >> 8);  b[offset + 7] = (byte)(x.Hi);
            b[offset + 8] = (byte)(x.Lo >> 56); b[offset + 9] = (byte)(x.Lo >> 48);
            b[offset +10] = (byte)(x.Lo >> 40); b[offset +11] = (byte)(x.Lo >> 32);
            b[offset +12] = (byte)(x.Lo >> 24); b[offset +13] = (byte)(x.Lo >> 16);
            b[offset +14] = (byte)(x.Lo >> 8);  b[offset +15] = (byte)(x.Lo);
        }

        public static Be128 Xor(Be128 a, Be128 b)
        {
            Be128 r; r.Hi = a.Hi ^ b.Hi; r.Lo = a.Lo ^ b.Lo; return r;
        }

        // right shift by 1 bit (big-endian logical value)
        public static Be128 Shr1(Be128 v)
        {
            Be128 r;
            r.Lo = (v.Lo >> 1) | ((v.Hi & 1UL) << 63);
            r.Hi = (v.Hi >> 1);
            return r;
        }

        // left shift by 1 bit
        public static Be128 Shl1(Be128 v)
        {
            Be128 r;
            r.Hi = (v.Hi << 1) | (v.Lo >> 63);
            r.Lo = (v.Lo << 1);
            return r;
        }

        // GF(2^128) multiplication per SP 800-38D, right-shift method
        public static Be128 GfMult(Be128 X, Be128 Y)
        {
            Be128 Z; Z.Hi = 0; Z.Lo = 0;
            Be128 V = Y;
            // R = 0xE1000000000000000000000000000000 (big-endian)
            Be128 R; R.Hi = 0xE100000000000000UL; R.Lo = 0x0000000000000000UL;

            for (int i = 0; i < 128; i++)
            {
                // test MSB of X
                bool msb = (X.Hi & 0x8000000000000000UL) != 0;
                if (msb) Z = Xor(Z, V);
                // update V
                bool lsb = (V.Lo & 1UL) != 0;
                V = Shr1(V);
                if (lsb) V = Xor(V, R);
                // shift X left
                X = Shl1(X);
            }
            return Z;
        }

        // GHASH update: Y <- (Y ^ X) * H
        public static void GhashUpdate(ref Be128 Y, byte[] H, byte[] block, int blockOffset)
        {
            Be128 X = LoadBE128(block, blockOffset);
            Y = GfMult(Xor(Y, X), LoadBE128(H, 0));
        }

        // Encrypt a single 16-byte block with GOST2-128
        public static void GostEncryptBlock(byte[] input, byte[] output, ulong[] key)
        {
            // convert input (big-endian) to two ulongs
            ulong a = ((ulong)input[0] << 56) | ((ulong)input[1] << 48) | ((ulong)input[2] << 40) | ((ulong)input[3] << 32) |
                      ((ulong)input[4] << 24) | ((ulong)input[5] << 16) | ((ulong)input[6] << 8) | ((ulong)input[7]);
            ulong b = ((ulong)input[8] << 56) | ((ulong)input[9] << 48) | ((ulong)input[10] << 40) | ((ulong)input[11] << 32) |
                      ((ulong)input[12] << 24) | ((ulong)input[13] << 16) | ((ulong)input[14] << 8) | ((ulong)input[15]);
            ulong[] inw = new ulong[] { a, b };
            ulong[] outw;
            cipher.gostcrypt(inw, out outw, key);
            // store big-endian
            output[0] = (byte)(outw[0] >> 56); output[1] = (byte)(outw[0] >> 48);
            output[2] = (byte)(outw[0] >> 40); output[3] = (byte)(outw[0] >> 32);
            output[4] = (byte)(outw[0] >> 24); output[5] = (byte)(outw[0] >> 16);
            output[6] = (byte)(outw[0] >> 8);  output[7] = (byte)(outw[0]);
            output[8] = (byte)(outw[1] >> 56); output[9] = (byte)(outw[1] >> 48);
            output[10] = (byte)(outw[1] >> 40); output[11] = (byte)(outw[1] >> 32);
            output[12] = (byte)(outw[1] >> 24); output[13] = (byte)(outw[1] >> 16);
            output[14] = (byte)(outw[1] >> 8);  output[15] = (byte)(outw[1]);
        }

        // inc32 on the last 32 bits of a 128-bit counter (big-endian)
        public static void Inc32(byte[] ctr)
        {
            uint c = ((uint)ctr[12] << 24) | ((uint)ctr[13] << 16) | ((uint)ctr[14] << 8) | ((uint)ctr[15]);
            c = (uint)((c + 1) & 0xFFFFFFFFU);
            ctr[12] = (byte)(c >> 24);
            ctr[13] = (byte)(c >> 16);
            ctr[14] = (byte)(c >> 8);
            ctr[15] = (byte)(c);
        }

        // Derive J0 from IV (generic case when IV != 12 bytes)
        public static void DeriveJ0(byte[] J0, byte[] iv, int ivlen, byte[] H)
        {
            // Y = 0
            Be128 Y; Y.Hi = 0; Y.Lo = 0;
            byte[] block = new byte[16];
            int off = 0;
            while (ivlen - off >= 16)
            {
                GhashUpdate(ref Y, H, iv, off);
                off += 16;
            }
            if (ivlen - off > 0)
            {
                Array.Clear(block, 0, 16);
                Array.Copy(iv, off, block, 0, ivlen - off);
                GhashUpdate(ref Y, H, block, 0);
            }
            // Append 128-bit length block: 64-bit zeros || [len(IV) in bits]_64
            Array.Clear(block, 0, 16);
            ulong ivbits = (ulong)ivlen * 8UL;
            // store as big-endian into block[8..15]
            block[8] = (byte)(ivbits >> 56); block[9] = (byte)(ivbits >> 48);
            block[10] = (byte)(ivbits >> 40); block[11] = (byte)(ivbits >> 32);
            block[12] = (byte)(ivbits >> 24); block[13] = (byte)(ivbits >> 16);
            block[14] = (byte)(ivbits >> 8);  block[15] = (byte)(ivbits);
            GhashUpdate(ref Y, H, block, 0);
            StoreBE128(Y, J0, 0);
        }

        // Prepares GHASH lengths block for AAD(empty) and C(lenC)
        public static void GhashLengthsUpdate(ref Be128 Y, byte[] H, ulong aad_bits, ulong c_bits)
        {
            byte[] lenblk = new byte[16];
            // [len(AAD)]_64 || [len(C)]_64 in bits, both big-endian
            // AAD=0 here so first 8 bytes zero
            lenblk[8] = (byte)(c_bits >> 56);
            lenblk[9] = (byte)(c_bits >> 48);
            lenblk[10] = (byte)(c_bits >> 40);
            lenblk[11] = (byte)(c_bits >> 32);
            lenblk[12] = (byte)(c_bits >> 24);
            lenblk[13] = (byte)(c_bits >> 16);
            lenblk[14] = (byte)(c_bits >> 8);
            lenblk[15] = (byte)(c_bits);
            GhashUpdate(ref Y, H, lenblk, 0);
        }

        // Constant-time tag comparison
        public static bool CtCompare(byte[] a, byte[] b, int n)
        {
            int r = 0;
            for (int i = 0; i < n; i++) r |= (a[i] ^ b[i]);
            return r == 0;
        }

        // Helper to generate 16 random bytes (IV)
        public static void GetIv16(byte[] iv)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }
        }

        // Encrypt file (streaming)
        public static int EncryptFile(string infile, string outfile, ulong[] key)
        {
            FileStream fi = null;
            FileStream fo = null;
            try
            {
                fi = new FileStream(infile, FileMode.Open, FileAccess.Read);
                fo = new FileStream(outfile, FileMode.Create, FileAccess.Write);

                // Compute H and J0
                byte[] H = new byte[16];
                ComputeH(H, key);
                // write IV
                byte[] iv = new byte[16];
                GetIv16(iv);
                fo.Write(iv, 0, 16);

                // Derive J0
                byte[] J0 = new byte[16];
                DeriveJ0(J0, iv, 16, H);

                // S = GHASH over ciphertext (starts at 0)
                Be128 S; S.Hi = 0; S.Lo = 0;

                // Counter starts from inc32(J0)
                byte[] ctr = new byte[16];
                Array.Copy(J0, 0, ctr, 0, 16);
                Inc32(ctr);

                byte[] inbuf = new byte[BUF_CHUNK];
                int r;
                ulong total_c_bytes = 0;

                while ((r = fi.Read(inbuf, 0, inbuf.Length)) > 0)
                {
                    int off = 0;
                    while (off < r)
                    {
                        byte[] ks = new byte[16];
                        byte[] cblk = new byte[16];
                        byte[] pblk = new byte[16];
                        int n = (r - off >= 16) ? 16 : (r - off);

                        // keystream = E_K(ctr)
                        GostEncryptBlock(ctr, ks, key);
                        Inc32(ctr);

                        // P block (pad with zeros for XOR; we only write n bytes)
                        Array.Clear(pblk, 0, 16);
                        Array.Copy(inbuf, off, pblk, 0, n);

                        for (int i = 0; i < n; i++) cblk[i] = (byte)(pblk[i] ^ ks[i]);
                        if (n < 16) for (int i = n; i < 16; i++) cblk[i] = 0; // pad for GHASH

                        // Update GHASH with ciphertext block (padded)
                        GhashUpdate(ref S, H, cblk, 0);

                        // Write ciphertext bytes (only n bytes)
                        fo.Write(cblk, 0, n);

                        total_c_bytes += (ulong)n;
                        off += n;
                    }
                }

                // finalize GHASH with lengths
                GhashLengthsUpdate(ref S, H, 0UL, total_c_bytes * 8UL);

                // Tag T = E_K(J0) XOR S
                byte[] EJ0 = new byte[16];
                GostEncryptBlock(J0, EJ0, key);
                byte[] Sbytes = new byte[16];
                StoreBE128(S, Sbytes, 0);
                byte[] Tag = new byte[16];
                for (int i = 0; i < 16; i++) Tag[i] = (byte)(EJ0[i] ^ Sbytes[i]);

                fo.Write(Tag, 0, 16);

                Console.WriteLine("Encryption completed. Wrote IV + ciphertext + tag.");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error: " + ex.Message);
                return -1;
            }
            finally
            {
                if (fi != null) fi.Close();
                if (fo != null) fo.Close();
            }
        }

        // Decrypt file (streaming, writes plaintext before authentication check)
        public static int DecryptFile(string infile, string outfile, ulong[] key)
        {
            FileStream fi = null;
            FileStream fo = null;
            try
            {
                fi = new FileStream(infile, FileMode.Open, FileAccess.Read);
                long fsz = fi.Length;
                if (fsz < 16 + 16)
                {
                    Console.Error.WriteLine("File too small (needs at least IV+TAG).");
                    return -1;
                }

                // Read IV
                byte[] iv = new byte[16];
                fi.Read(iv, 0, 16);
                long remaining = fsz - 16;
                if (remaining < 16)
                {
                    Console.Error.WriteLine("Missing tag.");
                    return -1;
                }
                long ciph_len = remaining - 16;

                fo = new FileStream(outfile, FileMode.Create, FileAccess.Write);

                // Compute H and J0
                byte[] H = new byte[16];
                ComputeH(H, key);
                byte[] J0 = new byte[16];
                DeriveJ0(J0, iv, 16, H);

                // GHASH S over ciphertext
                Be128 S; S.Hi = 0; S.Lo = 0;

                // CTR starts at inc32(J0)
                byte[] ctr = new byte[16];
                Array.Copy(J0, 0, ctr, 0, 16);
                Inc32(ctr);

                byte[] buf = new byte[BUF_CHUNK];
                long left = ciph_len;

                while (left > 0)
                {
                    int to_read = (left > BUF_CHUNK) ? BUF_CHUNK : (int)left;
                    int r = fi.Read(buf, 0, to_read);
                    if (r != to_read)
                    {
                        Console.Error.WriteLine("Read ciphertext failed.");
                        return -1;
                    }

                    int off = 0;
                    while (off < r)
                    {
                        byte[] ks = new byte[16];
                        byte[] cblk = new byte[16];
                        byte[] pblk = new byte[16];
                        int n = (r - off >= 16) ? 16 : (r - off);

                        // Prepare ciphertext block with zero padding for GHASH
                        Array.Clear(cblk, 0, 16);
                        Array.Copy(buf, off, cblk, 0, n);

                        // GHASH over ciphertext block
                        GhashUpdate(ref S, H, cblk, 0);

                        // keystream
                        GostEncryptBlock(ctr, ks, key);
                        Inc32(ctr);

                        // P = C XOR KS (only n bytes)
                        for (int i = 0; i < n; i++) pblk[i] = (byte)(cblk[i] ^ ks[i]);

                        fo.Write(pblk, 0, n);

                        off += n;
                    }

                    left -= to_read;
                }

                // Read trailing tag
                byte[] Tag = new byte[16];
                int tr = fi.Read(Tag, 0, 16);
                if (tr != 16)
                {
                    Console.Error.WriteLine("Read tag failed.");
                    return -1;
                }

                // Finalize GHASH with lengths
                ulong c_bits = (ulong)ciph_len * 8UL;
                GhashLengthsUpdate(ref S, H, 0UL, c_bits);

                byte[] EJ0 = new byte[16];
                GostEncryptBlock(J0, EJ0, key);
                byte[] Sbytes = new byte[16];
                StoreBE128(S, Sbytes, 0);
                byte[] Tcalc = new byte[16];
                for (int i = 0; i < 16; i++) Tcalc[i] = (byte)(EJ0[i] ^ Sbytes[i]);

                bool ok = CtCompare(Tag, Tcalc, 16);
                if (ok)
                {
                    Console.WriteLine("Authentication: OK");
                    return 0;
                }
                else
                {
                    Console.WriteLine("Authentication: FAILED");
                    return 1;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error: " + ex.Message);
                return -1;
            }
            finally
            {
                if (fi != null) fi.Close();
                if (fo != null) fo.Close();
            }
        }

        // Derive GOST2-128 subkeys from password
        public static void DeriveKeyFromPassword(string pwd, out ulong[] key)
        {
            byte[] h4 = new byte[512];
            hasher = new Gost2Hasher();
            // hashing password bytes
            byte[] pwdBytes = Encoding.ASCII.GetBytes(pwd);
            hasher.hashing(pwdBytes, pwdBytes.Length);
            hasher.end(h4);
            hasher.create_keys(h4, out key);
            // zero sensitive buffers
            for (int i = 0; i < pwdBytes.Length; i++) pwdBytes[i] = 0;
        }
    }
    // --- END: GCM wrapper ---

    class Program
    {
        static void Usage(string prog)
        {
            Console.Error.WriteLine("Usage: {0} c|d <input_file>", prog);
        }

        // Read password without echo
        static string ReadPassword()
        {
            StringBuilder sb = new StringBuilder();
            Console.Write("Enter password: ");
            ConsoleKeyInfo key;
            while (true)
            {
                key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (sb.Length > 0) sb.Length--;
                }
                else
                {
                    sb.Append(key.KeyChar);
                }
            }
            Console.WriteLine();
            return sb.ToString();
        }

        static void AddSuffixGost2(string inname, out string outname)
        {
            outname = inname + ".gost2";
        }

        static void StripSuffixGost2(string inname, out string outname)
        {
            string suf = ".gost2";
            if (inname.Length > suf.Length && inname.EndsWith(suf, StringComparison.OrdinalIgnoreCase))
            {
                outname = inname.Substring(0, inname.Length - suf.Length);
            }
            else
            {
                outname = inname + ".dec";
            }
        }

        static int Main(string[] args)
        {
            if (args == null || args.Length != 2)
            {
                Usage(AppDomain.CurrentDomain.FriendlyName);
                return 2;
            }

            string mode = args[0];
            string infile = args[1];

            string pwd = ReadPassword();
            if (pwd == null)
            {
                Console.Error.WriteLine("Failed to read password.");
                return 2;
            }

            // init GOST2 tables and derive subkeys from password
            ulong[] key;
            GcmGost2.DeriveKeyFromPassword(pwd, out key);
            // zero password string if possible
            pwd = null;

            string outfile;
            if (mode.Length > 0 && (mode[0] == 'c' || mode[0] == 'C'))
            {
                AddSuffixGost2(infile, out outfile);
                int rc = GcmGost2.EncryptFile(infile, outfile, key);
                return (rc == 0) ? 0 : 1;
            }
            else if (mode.Length > 0 && (mode[0] == 'd' || mode[0] == 'D'))
            {
                StripSuffixGost2(infile, out outfile);
                int rc = GcmGost2.DecryptFile(infile, outfile, key);
                return (rc == 0) ? 0 : 1;
            }
            else
            {
                Usage(AppDomain.CurrentDomain.FriendlyName);
                return 2;
            }
        }
    }
}
