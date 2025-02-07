using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;

namespace rsaasiff2
{
    class Program
    {
        static void Main()
        {

            try
            {
                string LoremText = "Lorem ipsum dolor sit amet, consectetur adipiscing veniam";
                Console.WriteLine("LOREM İPMUS METNİ: " + LoremText);
                Console.WriteLine();

                RSAParameters publicKey;
                Stopwatch stopwatch = new Stopwatch();

                stopwatch.Start();
                string encryptedText = EncryptText(LoremText, out publicKey, stopwatch);
                stopwatch.Stop();
                Console.WriteLine("ŞİFRELENMİŞ METİN: " + encryptedText);
                Console.WriteLine($"Şifreleme Süresi: {stopwatch.Elapsed.TotalSeconds} saniye\n");

                stopwatch.Reset();

                stopwatch.Start();
                string decryptedText = DecryptText(encryptedText, publicKey, stopwatch);
                stopwatch.Stop();
                Console.WriteLine("ÇÖZÜLEN METİN: " + decryptedText);
                Console.WriteLine($"Çözme Süresi: {stopwatch.Elapsed.TotalSeconds} saniye");
            }
            catch (Exception ex)
            {
                Console.WriteLine("HATA OLUŞTU: " + ex.Message);
            }

            Console.ReadKey();
        }

        public static byte[] ConvertToBytes(string value)
        {
            UnicodeEncoding byteConverter = new UnicodeEncoding();
            return byteConverter.GetBytes(value);
        }

        public static string EncryptText(string input, out RSAParameters publicKey, Stopwatch stopwatch)
        {
            string result = "";
            if (string.IsNullOrEmpty(input))
            {
                throw new ArgumentNullException("Şifrelenecek Metin Yok");
            }
            else
            {
                byte[] inputBytes = ConvertToBytes(input);
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(16384)) // işlem yaklaşık olarak beş dakika sürebilir.
                {
                    stopwatch.Start();
                    publicKey = rsa.ExportParameters(true);
                    byte[] encryptedBytes = rsa.Encrypt(inputBytes, false);
                    stopwatch.Stop();
                    result = Convert.ToBase64String(encryptedBytes);
                }
            }
            return result;
        }

        public static string DecryptText(string input, RSAParameters publicKey, Stopwatch stopwatch)
        {
            string result = "";
            if (string.IsNullOrEmpty(input))
            {
                throw new ArgumentNullException("Çözülecek Metin Yok");
            }
            else
            {
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(16384)) 
                {
                    byte[] inputBytes = Convert.FromBase64String(input);
                    UnicodeEncoding unicodeEncoder = new UnicodeEncoding();
                    rsa.ImportParameters(publicKey);

                    stopwatch.Start();
                    byte[] decryptedBytes = rsa.Decrypt(inputBytes, false);
                    stopwatch.Stop();
                    result = unicodeEncoder.GetString(decryptedBytes);
                }
            }
            return result;
        }
    }
}