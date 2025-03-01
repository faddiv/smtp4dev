﻿using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Rnwood.Smtp4dev.Server
{
    public static class CertificateHelper
    {
        /// <summary>
        /// Load certificate and private key
        /// </summary>
        /// <param name="certificatePath"></param>
        /// <param name="certificateKeyPath"></param>
        /// <returns>Exported x509 Certificate</returns>
        public static X509Certificate2 LoadCertificateWithKey(string certificatePath, string certificateKeyPath)
        {
            using var rsa = RSA.Create();
            var keyPem = File.ReadAllText(certificateKeyPath);
            var keyDer = CertificateHelper.UnPem(keyPem);
            rsa.ImportPkcs8PrivateKey(keyDer, out _);
            var certNoKey = new X509Certificate2(certificatePath);
            return new X509Certificate2(certNoKey.CopyWithPrivateKey(rsa).Export(X509ContentType
                .Pfx));
        }

        public static X509Certificate2 LoadCertificate(string certificatePath, string password="")
        {
            return new X509Certificate2(certificatePath, password);
        }

        public static X509Certificate2 LoadCertificateFromStore(string storeName, StoreLocation storeLocation, X509FindType x509FindType, string findValue)
        {
            using var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            var certificates = store.Certificates.Find(x509FindType, findValue, false);
            foreach (var cert in certificates)
            {
                if(cert.Verify())
                {
                    return cert;
                }
            }
            return certificates.Count > 0 ? certificates[0] : null;
        }

        /// <summary>
        /// This is a shortcut that assumes valid PEM
        /// -----BEGIN words-----\r\nbase64\r\n-----END words-----
        /// </summary>
        /// <param name="pem"></param>
        /// <returns></returns>
        public static byte[] UnPem(string pem)
        {
            const string dashes = "-----";
            const string newLine = "\r\n";
            pem = NormalizeLineEndings(pem);
            var index0 = pem.IndexOf(dashes, StringComparison.Ordinal);
            var index1 = pem.IndexOf(newLine, index0 + dashes.Length, StringComparison.Ordinal) + newLine.Length;
            var index2 = pem.IndexOf(dashes, index1, StringComparison.Ordinal) - newLine.Length; //TODO: /n
            return Convert.FromBase64String(pem.Substring(index1, index2 - index1));
        }

        private static string NormalizeLineEndings(string val)
        {
            return Regex.Replace(val, @"\r\n|\n\r|\n|\r", "\r\n");
        }
    }
}