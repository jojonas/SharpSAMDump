using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpSAMDump
{
    public class DPAPIBlob
    {
        public readonly int Version;
        public readonly byte[] MachineKey;
        public readonly byte[] UserKey;

        public DPAPIBlob(byte[] blob)
        {
            int offset = 0;

            Version = BitConverter.ToInt32(blob, offset);
            offset += 4;

            MachineKey = new byte[20];
            Array.Copy(blob, offset, MachineKey, 0, MachineKey.Length);
            offset += MachineKey.Length;

            UserKey = new byte[20];
            Array.Copy(blob, offset, UserKey, 0, UserKey.Length);
            offset += UserKey.Length;
        }
    }
}
