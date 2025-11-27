using Microsoft.Win32.SafeHandles;
using Microsoft.Win32;
using System.ComponentModel;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Registry;
using System;
using System.Security.Cryptography;
using System.Text;

namespace SharpSAMDump
{
    public static class RegistryExtension
    {
        public static RegistryKey OpenSubKeyForBackup(this RegistryKey key, string name)
        {
            SafeRegistryHandle hRegistry;

            WIN32_ERROR error = PInvoke.RegOpenKeyEx(
                key.Handle,
                name,
                (uint)REG_OPEN_CREATE_OPTIONS.REG_OPTION_BACKUP_RESTORE,
                REG_SAM_FLAGS.KEY_READ,
                out hRegistry);

            if (error != WIN32_ERROR.NO_ERROR)
            {
                throw new Win32Exception((int)error);
            }

            return RegistryKey.FromHandle(hRegistry);
        }

        public static string GetClassName(this RegistryKey key)
        {
            uint bufferSize = 256;
            Span<char> buffer = stackalloc char[(int)bufferSize];
            PInvoke.RegQueryInfoKey(key.Handle, buffer, ref bufferSize, out _, out _, out _, out _, out _, out _, out _, out _);
            return buffer.Slice(0, (int)bufferSize).ToString();
        }
    }
}
