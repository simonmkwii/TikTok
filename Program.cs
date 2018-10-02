using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace TikTok
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine($"Usage: TikTok.exe [-setup PRODINFO.bin] ticket.bin");
            }
            else
            {
                RSAParameters Params;
                if (!Directory.Exists("RSA") && args[0] == "-setup")
                {
                    var ProdFile = File.Open(args[1], FileMode.Open);
                    var ProdInfo = new BinaryReader(ProdFile);

                    Console.Write("Input the eticket rsa keypair decryption key: ");

                    var Key = HexStrToB(Console.ReadLine());

                    if (!Hex(new SHA256CryptoServiceProvider().ComputeHash(Key)).Equals("46cccf288286e31c931379de9efa288c95c9a15e40b00a4c563a8be244ece515"))
                    {
                        throw new ArgumentException("Invalid key!");
                    }

                    ProdFile.Position += 0x3890;

                    byte[] DecryptedData = AES_CTR(Key, ProdInfo.ReadBytes(0x10), ProdInfo.ReadBytes(0x230));

                    ProdInfo.Close();
                    ProdFile.Close();

                    BigInteger D = RSAUtils.GetBigInteger(DecryptedData.Take(0x100).ToArray());
                    BigInteger N = RSAUtils.GetBigInteger(DecryptedData.Skip(0x100).Take(0x100).ToArray());
                    BigInteger E = RSAUtils.GetBigInteger(DecryptedData.Skip(0x200).Take(0x4).ToArray());

                    Params = RSAUtils.RecoverRSAParameters(N, E, D);

                    Directory.CreateDirectory("RSA");

                    File.WriteAllBytes("RSA/mod.bin", Params.Modulus);
                    File.WriteAllBytes("RSA/exp.bin", Params.Exponent);
                    File.WriteAllBytes("RSA/d.bin", Params.D);
                    File.WriteAllBytes("RSA/p.bin", Params.P);
                    File.WriteAllBytes("RSA/q.bin", Params.Q);
                    File.WriteAllBytes("RSA/dp.bin", Params.DP);
                    File.WriteAllBytes("RSA/dq.bin", Params.DQ);
                    File.WriteAllBytes("RSA/invq.bin", Params.InverseQ);

                    Console.WriteLine("RSA parameters saved successfully!");

                    Environment.Exit(0);
                }
                else
                {
                    Params = new RSAParameters
                    {
                        Modulus = File.ReadAllBytes("RSA/mod.bin"),
                        Exponent = File.ReadAllBytes("RSA/exp.bin"),
                        D = File.ReadAllBytes("RSA/d.bin"),
                        P = File.ReadAllBytes("RSA/p.bin"),
                        Q = File.ReadAllBytes("RSA/q.bin"),
                        DP = File.ReadAllBytes("RSA/dp.bin"),
                        DQ = File.ReadAllBytes("RSA/dq.bin"),
                        InverseQ = File.ReadAllBytes("RSA/invq.bin")
                    };
                }

                var F = File.ReadAllBytes(args[0]);

                string Hex(byte[] In)
                {
                    return BitConverter.ToString(In).Replace("-", "").ToLower();
                }

                var Output = File.OpenWrite("title.keys");
                var Writer = new StreamWriter(Output);

                var RSA = new RSACng();
                RSA.ImportParameters(Params);

                for (int i = 0; i < F.Length / 0x400; i++)
                {
                    try
                    {
                        var Dec = Decrypt_RSA_OAEP_SHA256(F.Skip((i * 0x400) + 0x180).Take(0x100).ToArray(), RSA);
                        var ID = F.Skip((i * 0x400) + 0x2A0);
                        Console.WriteLine($"Ticket {i}:");
                        Console.WriteLine($"    Rights ID:  {Hex(ID.Take(0x10).ToArray())}");
                        Console.WriteLine($"    Title ID:   {Hex(ID.Take(0x8).ToArray())}");
                        Console.WriteLine($"    Titlekey:   {Hex(Dec)}");
                        Writer.WriteLine($"{Hex(ID.Take(0x10).ToArray())} = {Hex(Dec)}");
                    }
                    catch (Exception)
                    {
                    }
                }
                Writer.Close();
                Output.Close();
                Console.WriteLine("Done!");
            }
        }

        static byte[] AES_CTR(byte[] Key, byte[] CTR, byte[] Data)
        {
            var AESCTR = new Aes128CounterMode(CTR);
            ICryptoTransform Transform;
            Transform = AESCTR.CreateDecryptor(Key, null);
            return Transform.TransformFinalBlock(Data, 0, Data.Length);
        }

        static byte[] Decrypt_RSA_OAEP_SHA256(byte[] Input, RSACng RSA)
        {
            var SHA256Padding = RSAEncryptionPadding.CreateOaep(HashAlgorithmName.SHA256);
            return RSA.Decrypt(Input, SHA256Padding);
        }

        public static byte[] HexStrToB(string Hex)
        {
            return Enumerable.Range(0, Hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(Hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}