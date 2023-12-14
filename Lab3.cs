using System;
using System.Text;

namespace GOST_28147_89
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] encrypted, decrypted;
            byte[] key256b = Encoding.ASCII.GetBytes("this_is_a_pasw_for_GOST_28147_89");

            byte[] buffer = new byte[1024];
            int position = 0;
            int ch;
            while ((ch = Console.Read()) != '\n' && position < buffer.Length - 1)
                buffer[position++] = (byte)ch;
            buffer[position] = 0;

            Console.WriteLine("Open message:");
            PrintArray(buffer, position);
            Console.WriteLine(Encoding.ASCII.GetString(buffer, 0, position));
            Console.WriteLine();

            encrypted = GOST_28147('E', key256b, buffer, position);
            Console.WriteLine("Encrypted message:");
            PrintArray(encrypted, encrypted.Length);
            Console.WriteLine(Encoding.ASCII.GetString(encrypted));
            Console.WriteLine();

            decrypted = GOST_28147('D', key256b, encrypted, encrypted.Length);
            Console.WriteLine("Decrypted message:");
            PrintArray(decrypted, decrypted.Length);
            Console.WriteLine(Encoding.ASCII.GetString(decrypted));
            Console.WriteLine();
        }

        static byte[] GOST_28147(char mode, byte[] key256b, byte[] from, int length)
        {
            length = length % 8 == 0 ? length : length + (8 - (length % 8));
            uint N1, N2;
            uint[] keys32b = Split256BitsTo32Bits(key256b);

            byte[] to = new byte[length];
            for (int i = 0; i < length; i += 8)
            {
                Split64BitsTo32Bits(Join8BitsTo64Bits(from, i), out N1, out N2);
                FeistelCipher(mode, ref N1, ref N2, keys32b);
                Split64BitsTo8Bits(Join32BitsTo64Bits(N1, N2), to, i);
            }

            return to;
        }

        static void FeistelCipher(char mode, ref uint block32b_1, ref uint block32b_2, uint[] keys32b)
        {
            switch (mode)
            {
                case 'E':
                case 'e':
                    for (int round = 0; round < 24; ++round)
                        RoundOfFeistelCipher(ref block32b_1, ref block32b_2, keys32b, round);

                    for (int round = 31; round >= 24; --round)
                        RoundOfFeistelCipher(ref block32b_1, ref block32b_2, keys32b, round);
                    break;
                case 'D':
                case 'd':
                    for (int round = 0; round < 8; ++round)
                        RoundOfFeistelCipher(ref block32b_1, ref block32b_2, keys32b, round);

                    for (int round = 31; round >= 8; --round)
                        RoundOfFeistelCipher(ref block32b_1, ref block32b_2, keys32b, round);
                    break;
            }
        }

        static void RoundOfFeistelCipher(ref uint block32b_1, ref uint block32b_2, uint[] keys32b, int round)
        {
            uint result_of_iter, temp;
            result_of_iter = (block32b_1 + keys32b[round % 8]) % uint.MaxValue;
            result_of_iter = SubstitutionTable(result_of_iter, round % 8);
            result_of_iter = (result_of_iter << 11) | (result_of_iter >> (32 - 11));
            temp = block32b_1;
            block32b_1 = result_of_iter ^ block32b_2;
            block32b_2 = temp;
        }

        static uint SubstitutionTable(uint block32b, int sbox_row)
        {
            byte[] blocks4bits = new byte[4];
            Split32BitsTo8Bits(block32b, blocks4bits);
            SubstitutionTableBy4Bits(blocks4bits, sbox_row);
            return Join4BitsTo32Bits(blocks4bits);
        }

        static void SubstitutionTableBy4Bits(byte[] blocks4b, int sbox_row)
        {
            byte block4b_1, block4b_2;
            for (int i = 0; i < 4; ++i)
            {
                block4b_1 = Sbox[sbox_row, blocks4b[i] & 0x0F];
                block4b_2 = Sbox[sbox_row, blocks4b[i] >> 4];
                blocks4b[i] = (byte)((block4b_2 << 4) | block4b_1);
            }
        }

        static uint[] Split256BitsTo32Bits(byte[] key256b)
        {
            uint[] keys32b = new uint[8];
            int p8 = 0;
            for (int i = 0; i < 8; ++i)
            {
                for (int j = 0; j < 4; ++j)
                {
                    keys32b[i] = (keys32b[i] << 8) | key256b[p8 + j];
                }
                p8 += 4;
            }
            return keys32b;
        }

        static void Split64BitsTo32Bits(ulong block64b, out uint block32b_1, out uint block32b_2)
        {
            block32b_2 = (uint)(block64b);
            block32b_1 = (uint)(block64b >> 32);
        }

        static void Split64BitsTo8Bits(ulong block64b, byte[] blocks8b, int offset)
        {
            for (int i = 0; i < 8; ++i)
            {
                blocks8b[offset + i] = (byte)(block64b >> ((7 - i) * 8));
            }
        }

        static void Split32BitsTo8Bits(uint block32b, byte[] blocks8b)
        {
            for (int i = 0; i < 4; ++i)
            {
                blocks8b[i] = (byte)(block32b >> (24 - (i * 8)));
            }
        }

        static ulong Join32BitsTo64Bits(uint block32b_1, uint block32b_2)
        {
            ulong block64b;
            block64b = block32b_2;
            block64b = (block64b << 32) | block32b_1;
            return block64b;
        }

        static ulong Join8BitsTo64Bits(byte[] blocks8b, int offset)
        {
            ulong block64b = 0;
            for (int i = 0; i < 8; ++i)
            {
                block64b = (block64b << 8) | blocks8b[offset + i];
            }
            return block64b;
        }

        static uint Join4BitsTo32Bits(byte[] blocks4b)
        {
            uint block32b = 0;
            for (int i = 0; i < 4; ++i)
            {
                block32b = (block32b << 8) | blocks4b[i];
            }
            return block32b;
        }

        static void PrintArray(byte[] array, int length)
        {
            Console.Write("[ ");
            for (int i = 0; i < length; ++i)
                Console.Write("{0} ", array[i]);
            Console.WriteLine("]");
        }

        static readonly byte[,] Sbox = {
            {0xF, 0xC, 0x2, 0xA, 0x6, 0x4, 0x5, 0x0, 0x7, 0x9, 0xE, 0xD, 0x1, 0xB, 0x8, 0x3},
            {0xB, 0x6, 0x3, 0x4, 0xC, 0xF, 0xE, 0x2, 0x7, 0xD, 0x8, 0x0, 0x5, 0xA, 0x9, 0x1},
            {0x1, 0xC, 0xB, 0x0, 0xF, 0xE, 0x6, 0x5, 0xA, 0xD, 0x4, 0x8, 0x9, 0x3, 0x7, 0x2},
            {0x1, 0x5, 0xE, 0xC, 0xA, 0x7, 0x0, 0xD, 0x6, 0x2, 0xB, 0x4, 0x9, 0x3, 0xF, 0x8},
            {0x0, 0xC, 0x8, 0x9, 0xD, 0x2, 0xA, 0xB, 0x7, 0x3, 0x6, 0x5, 0x4, 0xE, 0xF, 0x1},
            {0x8, 0x0, 0xF, 0x3, 0x2, 0x5, 0xE, 0xB, 0x1, 0xA, 0x4, 0x7, 0xC, 0x9, 0xD, 0x6},
            {0x3, 0x0, 0x6, 0xF, 0x1, 0xE, 0x9, 0x2, 0xD, 0x8, 0xC, 0x4, 0xB, 0xA, 0x5, 0x7},
            {0x1, 0xA, 0x6, 0x8, 0xF, 0xB, 0x0, 0x4, 0xC, 0x3, 0x5, 0x9, 0x7, 0xD, 0x2, 0xE},
        };
    }
}