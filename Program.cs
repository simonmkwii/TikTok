using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace TikTok
{
    internal class Program
    {
        public static readonly byte[] KeyHash =
        {
            0x46, 0xCC, 0xCF, 0x28, 0x82, 0x86, 0xE3, 0x1C,
            0x93, 0x13, 0x79, 0xDE, 0x9E, 0xFA, 0x28, 0x8C,
            0x95, 0xC9, 0xA1, 0x5E, 0x40, 0xB0, 0x0A, 0x4C,
            0x56, 0x3A, 0x8B, 0xE2, 0x44, 0xEC, 0xE5, 0x15
        };

        private static void Main(string[] args)
        {
            if (args.Length < 1) Console.WriteLine($"Usage: TikTok.exe [-setup PRODINFO.bin] ticket.bin");
            else
            {
                RSAParameters Params;
                if (!Directory.Exists("RSA") && args[0] == "-setup")
                {
                    var ProdFile = File.Open(args[1], FileMode.Open);
                    var ProdInfo = new BinaryReader(ProdFile);

                    Console.Write("Input the eticket rsa keypair decryption key: ");

                    var Key = HexStrToB(Console.ReadLine());

                    if (!Hash(Key).SequenceEqual(KeyHash))
                        throw new ArgumentException("Invalid key!");

                    ProdFile.Position += 0x3890;

                    byte[] DecryptedData = Ctr(Key, ProdInfo.ReadBytes(0x10), ProdInfo.ReadBytes(0x230));

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

                var Output = File.OpenWrite("title.keys");
                var Writer = new StreamWriter(Output);

                var RSA = new RSACng();
                RSA.ImportParameters(Params);

                for (int i = 0; i < F.Length / 0x400; i++)
                {
                    try
                    {
                        var Dec = DecryptRsa(F.Skip((i * 0x400) + 0x180).Take(0x100).ToArray(), RSA);
                        var ID = F.Skip((i * 0x400) + 0x2A0);
                        Console.WriteLine($"\nTicket {i}:\n    Rights ID: {Hex(ID.Take(0x10).ToArray())}\n    Title ID:  {Hex(ID.Take(0x8).ToArray())}\n    Titlekey:  {Hex(Dec)}");
                        Writer.WriteLine($"{Hex(ID.Take(0x10).ToArray())} = {Hex(Dec)}");
                    }
                    catch { }
                }
                Writer.Close();
                Output.Close();
                Console.WriteLine("\a\nDone!");
            }
        }

        private static byte[] Ctr(byte[] Key, byte[] CTR, byte[] Data) => new Aes128CounterMode(CTR).CreateDecryptor(Key, null).TransformFinalBlock(Data, 0, Data.Length);

        private static byte[] Hash(byte[] In) => new SHA256CryptoServiceProvider().ComputeHash(In);

        private static byte[] DecryptRsa(byte[] Input, RSACng RSA) => RSA.Decrypt(Input, RSAEncryptionPadding.CreateOaep(HashAlgorithmName.SHA256));

        private static byte[] HexStrToB(string Hex) => Enumerable.Range(0, Hex.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(Hex.Substring(x, 2), 16)).ToArray();

        private static string Hex(byte[] In) => BitConverter.ToString(In).Replace("-", "").ToLower();
    }
}
