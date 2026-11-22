using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Credentials.UI;

namespace ZeroLeakage.UI.Services;

/// <summary>
/// Confirms it's really the PC's user before a sensitive action (e.g. Restore Defaults):
/// Windows Hello (PIN, fingerprint, face) when set up, otherwise Windows' own password prompt for the
/// signed-in account, checked by Windows itself. ZeroLeakage never sees or stores the PIN/biometric,
/// and the password (fallback only) is used once for the check and immediately discarded.
/// </summary>
public static class WindowsAuth
{
    public static async Task<bool> VerifyAsync(IntPtr owner, string reason)
    {
        try
        {
            if (await UserConsentVerifier.CheckAvailabilityAsync() == UserConsentVerifierAvailability.Available)
            {
                var result = await UserConsentVerifierInterop.RequestVerificationForWindowAsync(owner, reason);
                return result == UserConsentVerificationResult.Verified;
            }
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
        return PromptPassword(owner, reason);
    }

    // ───────────────────────── fallback: CredUI + LogonUser ─────────────────────────

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDUI_INFO
    {
        public int cbSize;
        public IntPtr hwndParent;
        public string pszMessageText;
        public string pszCaptionText;
        public IntPtr hbmBanner;
    }

    private const int CREDUIWIN_ENUMERATE_CURRENT_USER = 0x200;
    private const int ERROR_CANCELLED = 1223;

    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    private static extern int CredUIPromptForWindowsCredentials(ref CREDUI_INFO info, int authError, ref uint authPackage,
        IntPtr inAuthBuffer, uint inAuthBufferSize, out IntPtr outAuthBuffer, out uint outAuthBufferSize, ref bool save, int flags);

    [DllImport("credui.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredUnPackAuthenticationBuffer(int flags, IntPtr authBuffer, uint authBufferSize,
        StringBuilder userName, ref int maxUserName, StringBuilder domainName, ref int maxDomainName, StringBuilder password, ref int maxPassword);

    [DllImport("ole32.dll")]
    private static extern void CoTaskMemFree(IntPtr ptr);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LogonUser(string user, string? domain, string password, int logonType, int provider, out IntPtr token);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private static bool PromptPassword(IntPtr owner, string reason)
    {
        var info = new CREDUI_INFO
        {
            cbSize = Marshal.SizeOf<CREDUI_INFO>(), hwndParent = owner,
            pszCaptionText = "ZeroLeakage", pszMessageText = reason,
        };
        int error = 0;
        for (int attempt = 0; attempt < 3; attempt++)
        {
            uint package = 0;
            bool save = false;
            int rc = CredUIPromptForWindowsCredentials(ref info, error, ref package, IntPtr.Zero, 0,
                out var buffer, out var size, ref save, CREDUIWIN_ENUMERATE_CURRENT_USER);
            if (rc == ERROR_CANCELLED || rc != 0) return false;
            try
            {
                var user = new StringBuilder(256); var domain = new StringBuilder(256); var pass = new StringBuilder(256);
                int u = user.Capacity, d = domain.Capacity, p = pass.Capacity;
                if (!CredUnPackAuthenticationBuffer(0, buffer, size, user, ref u, domain, ref d, pass, ref p)) return false;
                string name = user.ToString(), dom = domain.ToString();
                if (dom.Length == 0 && name.Contains('\\')) { dom = name[..name.IndexOf('\\')]; name = name[(name.IndexOf('\\') + 1)..]; }
                bool ok = LogonUser(name, dom.Length > 0 ? dom : ".", pass.ToString(), 2 /* interactive */, 0, out var token);
                pass.Clear();
                if (ok)
                {
                    CloseHandle(token);
                    return true;
                }
                error = Marshal.GetLastWin32Error();   // shows "incorrect password" on the next prompt
            }
            finally
            {
                // wipe the packed credentials before freeing them
                if (buffer != IntPtr.Zero)
                {
                    Marshal.Copy(new byte[size], 0, buffer, (int)size);
                    CoTaskMemFree(buffer);
                }
            }
        }
        return false;
    }
}
