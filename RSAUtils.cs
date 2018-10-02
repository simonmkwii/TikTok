using System;
using System.Numerics;
using System.Security.Cryptography;

namespace TikTok
{
    // Source: https://stackoverflow.com/a/44441955
    internal class RSAUtils
    {
        public static BigInteger GetBigInteger(byte[] Input)
        {
            byte[] B = new byte[Input.Length + 1];
            Buffer.BlockCopy(Input, 0, B, 1, Input.Length);
            Array.Reverse(B);
            return new BigInteger(B);
        }

        public static byte[] GetBytes(BigInteger Input, int Len)
        {
            byte[] Bytes = Input.ToByteArray();
            Len = Bytes.Length;
            Array.Resize(ref Bytes, Len);
            Array.Reverse(Bytes);
            return Bytes;
        }

        public static BigInteger ModInverse(BigInteger Exp, BigInteger Mod)
        {
            BigInteger N = Mod;
            BigInteger E = Exp;
            BigInteger T = 0;
            BigInteger A = 1;
            while (E != 0)
            {
                BigInteger Q = N / E;
                BigInteger Val;
                Val = T;
                T = A;
                A = Val - Q * A;
                Val = N;
                N = E;
                E = Val - Q * E;
            }
            if (T < 0)
            {
                T = T + Mod;
            }
            return T;
        }

        public static RSAParameters RecoverRSAParameters(BigInteger n, BigInteger e, BigInteger d)
        {
            using (RandomNumberGenerator RNG = RandomNumberGenerator.Create())
            {
                BigInteger k = d * e - 1;
                BigInteger two = 2;
                BigInteger t = 1;
                BigInteger r = k / two;

                while (r.IsEven)
                {
                    t++;
                    r /= two;
                }

                byte[] Buf = n.ToByteArray();

                if (Buf[Buf.Length - 1] == 0)
                {
                    Buf = new byte[Buf.Length - 1];
                }

                BigInteger nMinusOne = n - 1;

                bool Done = false;
                BigInteger y = BigInteger.Zero;

                for (int i = 0; i < 100 && !Done; i++)
                {
                    BigInteger g;

                    do
                    {
                        RNG.GetBytes(Buf);
                        g = GetBigInteger(Buf);
                    }
                    while (g >= n);

                    y = BigInteger.ModPow(g, r, n);

                    if (y.IsOne || y == nMinusOne)
                    {
                        i--;
                        continue;
                    }

                    for (BigInteger j = 1; j < t; j++)
                    {
                        BigInteger x = BigInteger.ModPow(y, two, n);

                        if (x.IsOne)
                        {
                            Done = true;
                            break;
                        }

                        if (x == nMinusOne)
                        {
                            break;
                        }

                        y = x;
                    }
                }

                BigInteger p = BigInteger.GreatestCommonDivisor(y - 1, n);
                BigInteger q = n / p;
                BigInteger dp = d % (p - 1);
                BigInteger dq = d % (q - 1);
                BigInteger inverseQ = ModInverse(q, p);

                int modLen = Buf.Length;
                int halfModLen = (modLen + 1) / 2;

                return new RSAParameters
                {
                    Modulus = GetBytes(n, modLen),
                    Exponent = GetBytes(e, -1),
                    D = GetBytes(d, modLen),
                    P = GetBytes(p, halfModLen),
                    Q = GetBytes(q, halfModLen),
                    DP = GetBytes(dp, halfModLen),
                    DQ = GetBytes(dq, halfModLen),
                    InverseQ = GetBytes(inverseQ, halfModLen),
                };
            }
        }
    }
}