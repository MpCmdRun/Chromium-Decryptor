
# ChromeDecryptor & Injector 🔥

**Extract App-Bound Encryption Keys from Chromium-based Browsers (Chrome, Brave, Edge)**

---

## 🚀 Overview

This toolkit consists of **two parts**:

- **Decryptor DLL** (`chrome_decrypt.dll`) - a small injected payload that extracts the encryption key from a browser process.
- **Injector EXE** (`ChromeInject.exe`) - a C# remote DLL injector that deploys the decryptor into a target browser.

---

## 🧩 Components

### 1. Decryptor (`chrome_decrypt.dll`)
- **Written in C/C++.**
- Loads inside the browser process (e.g., Chrome).
- Extracts the App-Bound Encryption Key.
- Saves key and log temporarily in `%TEMP%` folder.

**Output:**  
- `chrome_appbound_key.txt` (the extracted encryption key)
- `chrome_decrypt.log` (optional debug log)

---

### 2. Injector (`ChromeInject.exe`)
- **Written in C# (.NET)**.
- Locates the target browser process (e.g., `chrome.exe`).
- Injects the `chrome_decrypt.dll` using `CreateRemoteThread` + `LoadLibraryW`.
- Optional auto-start browser if not running.
- Colorful console output and verbose logging.
- Automatic cleanup of temporary key and log files after extraction.

---

## ⚙️ Build Instructions

### Build the Decryptor (DLL)
1. Open `chrome_decrypt` project in Visual Studio.
2. Set Configuration to **Release** and Platform to **x64**.
3. Build the DLL.

_Important:_ Compile as a **DLL**, not EXE.

---

### Build the Injector (EXE)
1. Open `ChromeInject` C# project in Visual Studio or Rider.
2. Set Configuration to **Release**.
3. Build the EXE.

_Target Framework:_ `.NET 6.0` or `.NET Framework 4.7.2+`.

---

## 🛠 Usage

### 1. Place Files Together
- `ChromeInject.exe`
- `chrome_decrypt.dll`

Must be in the **same folder**.

---

### 2. Run the Injector

```bash
ChromeInject.exe [options] <chrome|brave|edge>
```

### Options

| Option            | Description                                |
| ----------------- | ------------------------------------------ |
| `--method load`   | Use LoadLibrary + CreateRemoteThread       |
| `--start-browser` | Auto-launch browser if not running         |
| `--verbose`       | Enable detailed console output            |

---

### Example

```bash
ChromeInject.exe --method load --start-browser --verbose chrome
```

> Injects into Chrome, starts it if necessary, shows detailed logs.

---

## 📦 Output Location

| File                     | Description                       |
| ------------------------- | --------------------------------- |
| `%TEMP%\chrome_appbound_key.txt` | The extracted encryption key |
| `%TEMP%\chrome_decrypt.log`      | Log file (optional)          |

Both files are automatically **deleted** after processing.

---

## 🔒 Disclaimer

This tool is provided for **educational and research purposes only**.  
The author is **not responsible** for any misuse, damage, or legal consequences.

Use responsibly. 🛡️

---

## ✨ Credits

- Original `chrome_decrypt.dll` concept by **@xaitax**.
- Injector C# port and improvements by **[MpCmdRun](https://github.com/MpCmdRun)**.

---

<p align="center">
  <b>Stay safe, and happy decrypting! 🔥</b>
</p>

