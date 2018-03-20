public class CriptografiaEfianceira
{
    public class retornoEncrypt
    {
        public string Chave { get; set; }
        public string Dados { get; set; }
    }
    
    public static retornoEncrypt EncryptStringToBytes_Aes(string plainText)
    {
        byte[] encrypted;
        byte[] IV;
        byte[] key = new byte[16];

        var retorno = new retornoEncrypt();

        using (var random = new RNGCryptoServiceProvider())
        {
            random.GetBytes(key);
        };

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;

            aesAlg.GenerateIV();
            IV = aesAlg.IV;

            aesAlg.Mode = CipherMode.CBC;

            var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for encryption. 
            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
        }

        var combinedIvkey = new byte[key.Length + IV.Length];
        Array.Copy(key, 0, combinedIvkey, 0, key.Length);
        Array.Copy(IV, 0, combinedIvkey, key.Length, IV.Length);

        retorno.Dados = Convert.ToBase64String(encrypted.ToArray());
        retorno.Chave = EncryptStringToBytes_Rsa(combinedIvkey);

        // Return the encrypted bytes from the memory stream. 
        return retorno;
    }
        
    private static string EncryptStringToBytes_Rsa(byte[] ketToEncrypt)
    {
        //Create a UnicodeEncoder to convert between byte array and string.
        UnicodeEncoding ByteConverter = new UnicodeEncoding();

        //Create byte arrays to hold original, encrypted, and decrypted data.
        byte[] encryptedData;

        //Create a new instance of RSACryptoServiceProvider to generate
        //public and private key data.

        #region pathCertificate
        string codeBase = System.Reflection.Assembly.GetExecutingAssembly().GetName().CodeBase;
        UriBuilder uri = new UriBuilder(codeBase);
        string directory = System.IO.Path.GetDirectoryName(uri.Path);
        string path = System.IO.Path.Combine(directory, "EFinanceira");
        if (!System.IO.Directory.Exists(path))
            path = directory;
        path = System.IO.Path.Combine(path, "preprod-efinancentreposto.receita.fazenda.gov.br.cer");

        #endregion

        X509Certificate2 cert = new X509Certificate2(path);


        using (RSACryptoServiceProvider RSA = (RSACryptoServiceProvider)cert.PublicKey.Key)
        {
            //Pass the data to ENCRYPT, the public key information 
            //(using RSACryptoServiceProvider.ExportParameters(false),
            //and a boolean flag specifying no OAEP padding.
            encryptedData = RSA.Encrypt(ketToEncrypt, false);
        }
        return Convert.ToBase64String(encryptedData);
    }
}
