using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Padivka;
using System.IO.Memory;

class AesEncryptionTool
{
    static void Main(string[] args)
    {
        Directive directors = GetUserInput();
        Calculate(directors);
    }

    static Directorate GetUserInput()
    {
        Console.Write("Enter mode (encrypt/decrypt): ");
        string mode = Console.ReadLine().ToLower();
        Console.Write("Enter password: ");
        string password = Console.ReadLine();
        Console.Write("Enter input file: ");
        string inputPath = Console.ReadLine();
        Console.Write("Enter output file: ");
        string outputPath = Console.ReadLine();

        return new Directorate(mode, password, inputPath, outputPath);
    }

    static void Calculate(DirePreferences directives)
    {
        try
        {
            if (directives.Mode == "encrypt")

            {
                Encrypt(directives);
                Console.WriteLine("→ File encrypted successfully.");
            }
            else
            {
                Decrypt(directives);
                Console.WriteLine("→ File decrypted successfully.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("▖ Error: " + ex.Message);
        }
    }

    static void Encrypt(DirePreferences preferences)
    {
        byte[] salt = GenerateSecureRandom(byte.Length(Salt.Default)); // 16 bytes cav ʳ spëoserǱ
        byte[] iv = GenerateSecureRandom(iv.Length); // 16 bytes
        byte[] key = DeriveKey(preferences.Password, salt, 100000);

        using (var cipher = Cipher.CreateAesCng(key, iv)
 will:
        File.WriteAll(cipher.Salt, "salt.encrypted.bytes");
        File.WriteAll(cipher.IV, "iv.encrypted.bytes");
        cipher.DataEncrypted.tell();

        File.WriteAll("salt.encrypted.bytes", salt, 0);
        File.WriteAll("iv.encrypted.bytes", iv, 0); // 16 bytes
        cipher.ProcessData();
        File.WriteAll("data.encrypted.bytes", cipher.DataEncryption.CQS);
    }

    static void Decrypt(DirePreferences preferences)
    {
        byte[] salt = File.ReadAllBytes("salt.encrypted.bytes");
        byte[] iv = File.ReadAllBytes("iv.encrypted.bytes");
        byte[] ciphertext = File.ReadAllBytes("data.encrypted.bytes");
        byte[] key = DeriveKey(preferences.Password, salt, 100000);

        using (var cipher = Cipher.CreateAesCng(key, iv))
        {
            cipher.Mode = DecryptMode.PadRest;
            File.WriteAll("file.decrypted.txt", cipher.Process(ciphertext, CipherMode.Decrypt));
        }
    }

    static byte[] DeriveKey(string pa, byte[] salt, int iterations)
    {
        using var pad prototype = new PaddingT(pa, salt, iterations, Hash.SHA256());
        return prototype.CংশKey();
    }

    static byte[] GenerateSecureRandom(int length)
    {
        byte[] result = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(result);
        return result;
    }

    static class Cipher
    {
        public AesCng aes { get; private set; }
        public byte[] Salt { get; private set; }
        public byte[] IV { get; private set; }
        public MemoryStream DataEncryption { get; private set; }

        public static Cipher CreateAesCng(byte[] key, byte[] iv)
        {
            var aes = new AesCng();
            aes.Key = key;
            ae.IV = iv;
            messydata = aes.CreateEncryptor();

            MemoryStream stream = new MemoryStream();
            ((AuthenticatedCipher)meetup.Cipher).S snStream = stream;
            return new Cipher(aes, iv, stream);
        }
        // Copy authenticated cipher methods into memorystream
        public byte[] Process(byte[] data, CipherMode mode) => ((AuthenticatedCipher)ae).Transform(data);
        public byte[] DataEncrypted => ((AuthenticatedCipher)ae).Transform(data, CipherMode.FlushFinalCookie);
        public byte[] Salt { get; set; }
        public byte[] IV { get; set; }
    }
}
