using Microsoft.Win32.SafeHandles;
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security;

namespace SharpSAMDump
{
    internal class Privileges
    {
        public const string SeBackupPrivilege = "SeBackupPrivilege";

        public static void EnablePrivilege(string name, bool enabled = true)
        {
            SafeFileHandle hToken = GetCurrentProcessToken(TOKEN_ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES | TOKEN_ACCESS_MASK.TOKEN_QUERY);
            LUID luid = LookupPrivilegeLUID(name);

            LUID_AND_ATTRIBUTES privileges = new LUID_AND_ATTRIBUTES()
            {
                Luid = luid,
                Attributes = enabled ? TOKEN_PRIVILEGES_ATTRIBUTES.SE_PRIVILEGE_ENABLED : 0,
            };

            TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES();
            tokenPrivileges.PrivilegeCount = 1;
            tokenPrivileges.Privileges.e0 = privileges;

            unsafe
            {
                if (!PInvoke.AdjustTokenPrivileges(hToken, false, &tokenPrivileges, null, out _))
                {
                    throw new Win32Exception();
                }
            }
        }

        private static SafeFileHandle GetCurrentProcessToken(TOKEN_ACCESS_MASK accessMask)
        {
            SafeFileHandle hProcess = PInvoke.GetCurrentProcess_SafeHandle();

            SafeFileHandle hToken;
            if (!PInvoke.OpenProcessToken(hProcess, accessMask, out hToken))
            {
                throw new Win32Exception();
            }

            return hToken;
        }

        private static LUID LookupPrivilegeLUID(string name)
        {
            LUID luid;
            if (!PInvoke.LookupPrivilegeValue(null, name, out luid))
            {
                throw new Win32Exception();
            }
            return luid;
        }

        private static string LookupPrivilegeName(LUID luid)
        {
            uint bufferSize = 256;
            Span<char> buffer = stackalloc char[(int)bufferSize];
            PInvoke.LookupPrivilegeName(null, luid, buffer, ref bufferSize);
            return buffer.Slice(0, (int)bufferSize).ToString();
        }
    }
}
