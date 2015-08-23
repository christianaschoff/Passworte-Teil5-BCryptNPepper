using CryptSharp;
using SHA3;
using System;
using System.IO;
using System.Reflection;
using System.Text;

namespace de.brockhausag.bcryptPepper
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("BCrypt und Peper Beispiel");
            Console.WriteLine("=========================");

            //Eingabe lesen und in ein Byte-Array verwandeln
            var password = Input();

            string pepper = LoadPepper();
            string bcrypt = BCryptPepper(password, pepper);

            Console.WriteLine("BCrypt+Pepper:\t{0}", bcrypt);
            Console.WriteLine("Passwort korrekt:\t{0}", CheckPassword(password, pepper, bcrypt));

            Console.WriteLine("Beliebige Taste drücken zum beenden");
            Console.ReadKey();
        }


        //BCrypt und Pepper
        private static string BCryptPepper(string password, string pepper)
        {
            var pepperedPassword = SHA3Pepper(password, pepper);
            var bcrypt = BlowfishCrypter.Blowfish.Crypt(pepperedPassword, BlowfishCrypter.Blowfish.GenerateSalt(new CrypterOptions { { CrypterOption.Variant, BlowfishCrypterVariant.Corrected }, { CrypterOption.Rounds, 10 } }));
            return bcrypt;           
        }
            

        //Erzeuge Pepper
        private static string SHA3Pepper(string password, string pepper)
        {
            var bytes = new ASCIIEncoding().GetBytes(string.Concat(password, pepper));
            var crypto = new SHA3Managed(256);
            var hash = crypto.ComputeHash(bytes);
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        //Passwort-Prüfung
        private static bool CheckPassword(string user_input_password, string pepper, string bcryptedPassword)
        {
            var pepperedPassword = SHA3Pepper(user_input_password, pepper);
            return BlowfishCrypter.CheckPassword(new ASCIIEncoding().GetBytes(pepperedPassword), bcryptedPassword);
        }


        /// <summary>
        /// Läd Pepper aus einer externen Quelle
        /// Zur Vereinfachung wurde hier eine eingebettete Resource verwendet
        /// Normaler Weise muss hier eine externe Quelle angebunden werden!
        /// Dies hätte aber die Lauffähigkeit des Demos erschwert
        /// </summary>
        /// <returns>Entschlüsselter Pepper Wert</returns>
        private static string LoadPepper()
        {
            using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("de.brockhausag.bcryptPepper.Base64EncodedPepper.txt"))
            {
                using (var encodedPepper = new StreamReader(stream))
                {
                    return Encoding.UTF8.GetString(Convert.FromBase64String(encodedPepper.ReadToEnd().ToString()));
                }
            }
        }

        private static string Input()
        {
            Console.Write("Bitte ein Kennwort eingeben: ");
            var password = string.Empty;

            while (string.IsNullOrEmpty(password))
                password = Console.ReadLine();
            return password;
        }       
    }
}
