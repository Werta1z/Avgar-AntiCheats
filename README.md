# Avgar AntiCheat

High-speed, zero-dependency forensic and runtime memory scanner for Minecraft screenshare (SS) checks. Powered by an inline multi-threaded C# engine via PowerShell.

## Detection Vectors
* **Memory & Injection Forensics:** Scans `javaw.exe` executable memory regions via WinAPI (`ReadProcessMemory`) for ghost client signatures and unbacked PE/DLL injections (Manual-Map / JNI).
* **JVM Bytecode Analysis:** Inspects `.jar` archives in memory without disk extraction to detect Mixin/Reflection hooks targeting hitboxes (`AxisAlignedBB`), reach, and combat packets.
* **OS & Registry Artifacts:** Audits Windows execution logs (`BAM` registry, `Prefetch`, `USN Journal`) to uncover previously launched cheats, loaders, and trace-cleaning utilities.
* **Network Footprint:** Checks the system DNS resolver cache for connections to known cheat authentication servers.

## Quick Launch
Open **PowerShell as Administrator** and run:

```powershell - paste txt

