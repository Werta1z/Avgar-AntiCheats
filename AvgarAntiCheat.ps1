#Requires -RunAsAdministrator
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "Avgar AntiCheat | Elite Runtime Scanner"

$OutputDir = if ($PSScriptRoot) { $PSScriptRoot } else { [Environment]::GetFolderPath('Desktop') }

$EngineCode = @"
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace AvgarEngine {
    public class ScanHit {
        public string Severity { get; set; }
        public string Type { get; set; }
        public string Target { get; set; }
        public string Details { get; set; }
    }

    public static class Scanner {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProc, IntPtr baseAddr, [Out] byte[] buf, int size, out IntPtr read);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProc, IntPtr addr, out MBI buf, uint len);
        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern uint GetMappedFileName(IntPtr hProc, IntPtr lpv, StringBuilder lpFile, uint nSize);
        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr h);

        public struct MBI {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        static readonly string[] Sigs = new string[] {
            "SystemDLC", "mhub_loader", "Cortex.dll", "EverDLC", "Nursultan", "Celestial", "Expensive", 
            "Wexside", "RichClient", "Akrien", "DeadCode", "NeverHook", "Wexium", "Mytheria", 
            "WildClient", "ThunderHack", "MeteorClient", "LiquidBounce", "Vape_V4", "VapeLite", 
            "Doomsday", "Slinky", "Entropy", "ExLoader", "LunarPatcher", "HitboxExpander", 
            "atributswap", "walksycustom", "Catlavan", "Zamorozka", "Boze", "Mathax", "JexClient", 
            "Ketamine", "DripLite", "Nightmares", "FDPClient", "RiseClient", "CryptClient"
        };

        static readonly string[] Cleaners = new string[] {
            "SS_Cleaner", "TraceCleaner", "USNJournalCleaner", "PrefetchCleaner", "BAMCleaner", 
            "RegCleaner", "AveyCleaner", "OceanCleaner", "EchoCleaner", "ViperCleaner", "AeroCleaner", 
            "Chameleon", "ModFaker", "Spoofer"
        };

        static readonly string[] Whitelist = new string[] { 
            "optifine", "sodium", "fabric-api", "forge", "iris", "lithium", "jei" 
        };

        public static bool CheckCert(string path) {
            try { return X509Certificate.CreateFromSignedFile(path) != null; } 
            catch { return false; }
        }

        public static List<ScanHit> ScanProcess(int pid) {
            var hits = new List<ScanHit>();
            IntPtr h = OpenProcess(0x0010 | 0x0400, false, pid);
            if (h == IntPtr.Zero) return hits;

            long addr = 0;
            MBI mbi;
            var seen = new HashSet<string>();
            var sb = new StringBuilder(512);

            try {
                while (VirtualQueryEx(h, (IntPtr)addr, out mbi, (uint)Marshal.SizeOf(typeof(MBI))) != 0) {
                    long size = (long)mbi.RegionSize;
                    
                    if (mbi.State == 0x1000 && (mbi.Protect == 0x40 || mbi.Protect == 0x20 || mbi.Protect == 0x80)) {
                        bool unbacked = (mbi.Type == 0x20000 && size >= 4096 && GetMappedFileName(h, mbi.BaseAddress, sb, 512) == 0);
                        int readSize = (int)Math.Min(size, 32 * 1024 * 1024);
                        byte[] buf = new byte[readSize];
                        
                        IntPtr read;
                        if (ReadProcessMemory(h, mbi.BaseAddress, buf, readSize, out read) && (int)read > 0) {
                            if (unbacked && buf.Length >= 2 && buf[0] == 0x4D && buf[1] == 0x5A) {
                                string key = "PE_" + mbi.BaseAddress;
                                if (seen.Add(key)) {
                                    hits.Add(new ScanHit { 
                                        Severity = "CRITICAL", 
                                        Type = "Manual Map Inject (Unbacked PE)", 
                                        Target = string.Format("PID:{0}@0x{1:X}", pid, (long)mbi.BaseAddress), 
                                        Details = "Исполняемый PE-файл в памяти без файла на диске (Лоадер)" 
                                    });
                                }
                            }

                            string text = Encoding.ASCII.GetString(buf, 0, (int)read);
                            foreach (var s in Sigs) {
                                if (text.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0 && seen.Add(s)) {
                                    hits.Add(new ScanHit { 
                                        Severity = "CRITICAL", 
                                        Type = "Сигнатура Чита (Память)", 
                                        Target = string.Format("PID:{0}", pid), 
                                        Details = string.Format("Найдено: {0}", s) 
                                    });
                                }
                            }
                            foreach (var c in Cleaners) {
                                if (text.IndexOf(c, StringComparison.OrdinalIgnoreCase) >= 0 && seen.Add(c)) {
                                    hits.Add(new ScanHit { 
                                        Severity = "CRITICAL", 
                                        Type = "Сигнатура Клинера", 
                                        Target = string.Format("PID:{0}", pid), 
                                        Details = string.Format("Найдено: {0}", c) 
                                    });
                                }
                            }
                        }
                    }
                    addr = (long)mbi.BaseAddress + size;
                }
            } finally { CloseHandle(h); }
            return hits;
        }

        public static List<ScanHit> ScanJar(string path) {
            var hits = new List<ScanHit>();
            try {
                string fName = Path.GetFileName(path).ToLower();
                foreach (var w in Whitelist) {
                    if (fName.Contains(w)) return hits;
                }

                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) {
                    byte[] hdr = new byte[2];
                    if (fs.Read(hdr, 0, 2) < 2 || hdr[0] != 0x50 || hdr[1] != 0x4B) return hits;
                    fs.Position = 0;

                    using (var zip = new ZipArchive(fs, ZipArchiveMode.Read)) {
                        var traits = new List<string>();
                        foreach (var ent in zip.Entries) {
                            if (!ent.FullName.EndsWith(".class") || ent.FullName.StartsWith("org/lwjgl")) continue;
                            
                            using (var ms = new MemoryStream()) {
                                ent.Open().CopyTo(ms);
                                string code = Encoding.ASCII.GetString(ms.ToArray());
                                
                                foreach (var s in Sigs) {
                                    if (code.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0 && !traits.Contains(s)) {
                                        traits.Add(string.Format("SIG:{0}", s));
                                    }
                                }
                                
                                if (code.Contains("spongepowered/asm/mixin") || code.Contains("java/lang/reflect")) {
                                    if (code.Contains("AxisAlignedBB") && code.Contains("expand(") && code.Contains("EntityPlayer")) {
                                        if(!traits.Contains("ASM_HITBOX_EXPANDER")) traits.Add("ASM_HITBOX_EXPANDER");
                                    }
                                    if (code.Contains("getBlockReachDistance") && code.Contains("ModifyReturnValue")) {
                                        if(!traits.Contains("ASM_REACH")) traits.Add("ASM_REACH");
                                    }
                                    if (code.Contains("C02PacketUseEntity") && code.Contains("onTick")) {
                                        if(!traits.Contains("ASM_KILLAURA_TICK")) traits.Add("ASM_KILLAURA_TICK");
                                    }
                                }
                            }
                        }
                        if (traits.Count > 0) {
                            hits.Add(new ScanHit { 
                                Severity = "CRITICAL", 
                                Type = "Вмешательство в байт-код JAR", 
                                Target = path, 
                                Details = string.Join(", ", traits.ToArray()) 
                            });
                        }
                    }
                }
            } catch { }
            return hits;
        }

        public static List<ScanHit> ScanJarsParallel(string[] paths) {
            var allHits = new ConcurrentBag<ScanHit>();

            Parallel.ForEach(paths, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, path => {
                var res = ScanJar(path);
                foreach (var r in res) {
                    allHits.Add(r);
                }
            });

            return allHits.ToList();
        }
    }
}
"@

try {
    Add-Type -TypeDefinition $EngineCode -Language CSharp -ReferencedAssemblies @("System.IO.Compression", "System.IO.Compression.FileSystem")
} catch {
    Write-Host "`n[FATAL ERROR] C# Engine Compilation Failed!" -ForegroundColor Red
    Write-Host "Message: $($_.Exception.Message)" -ForegroundColor Gray
    Read-Host "Press Enter to exit..."
    exit
}

# --- ПРОФИЛИРОВАНИЕ ЖЕЛЕЗА И РАСЧЕТ ETA ---
$CpuCores = [Environment]::ProcessorCount
$TotalRam = [Math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
$DiskType = "SSD"
try { $DiskType = (Get-PhysicalDisk | Select-Object -First 1).MediaType } catch {}

$JavawProcs = Get-Process "javaw" -ErrorAction SilentlyContinue
$JavawMem = 0
foreach ($p in $JavawProcs) { $JavawMem += ($p.WorkingSet64 / 1MB) }

$JarFiles = [System.Collections.Generic.List[string]]::new()
$SearchDirs = @(
    @{ Path = (Join-Path $env:APPDATA ".minecraft\mods"); Depth = 3 },
    @{ Path = $env:TEMP; Depth = 2 },
    @{ Path = (Join-Path $env:USERPROFILE "Downloads"); Depth = 2 }
)

foreach ($sd in $SearchDirs) {
    if (Test-Path $sd.Path) {
        Get-ChildItem -Path $sd.Path -Depth $sd.Depth -File -Filter "*.jar" -ErrorAction SilentlyContinue | ForEach-Object {
            $JarFiles.Add($_.FullName)
        }
    }
}

$DiskMult = if ($DiskType -match "HDD") { 2.5 } else { 1.0 }
$CpuMult = if ($CpuCores -ge 12) { 0.6 } elseif ($CpuCores -ge 8) { 0.8 } else { 1.2 }
$TotalEstSec = [Math]::Ceiling((($JavawMem / 500) * $CpuMult) + ($JarFiles.Count * 0.15 * $DiskMult) + 3.0)
if ($TotalEstSec -lt 4) { $TotalEstSec = 4 }

$Sw = [System.Diagnostics.Stopwatch]::StartNew()
$Hits = [System.Collections.Generic.List[PSCustomObject]]::new()
function Register-Hit($Level, $Type, $Target, $Details) {
    $Hits.Add([PSCustomObject]@{ Level=$Level; Type=$Type; Target=$Target; Details=$Details })
}

function Update-UI($Stage, $Pct) {
    $Rem = $TotalEstSec - $Sw.Elapsed.TotalSeconds
    if ($Rem -lt 0) { $Rem = 0 }
    
    $BarWidth = 40
    $Filled = [Math]::Floor(($Pct / 100) * $BarWidth)
    $Bar = ("█" * $Filled) + ("░" * ($BarWidth - $Filled))
    
    [Console]::SetCursorPosition(0,0)
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host " AVGAR ANTICHEAT CORE | SYSTEM SCANNER" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host (" [SYS] CPU: ${CpuCores}C | RAM: ${TotalRam}GB | DISK: ${DiskType}") -ForegroundColor DarkGray
    Write-Host (" [TGT] JVM Memory: $([Math]::Round($JavawMem)) MB | Files to scan: $($JarFiles.Count)") -ForegroundColor DarkGray
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host (" TASK : " + $Stage.PadRight(60)) -ForegroundColor White
    Write-Host (" PROG : [" + $Bar + "] $Pct% (ETA: $([Math]::Round($Rem))s)   ") -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Cyan
}

Clear-Host
Update-UI "Сканирование оперативной памяти..." 10

foreach ($jp in $JavawProcs) {
    $Res = [AvgarEngine.Scanner]::ScanProcess($jp.Id)
    foreach ($r in $Res) { Register-Hit $r.Severity $r.Type $r.Target $r.Details }
}

Update-UI "Многопоточный анализ байт-кода .jar..." 40

if ($JarFiles.Count -gt 0) {
    $JarRes = [AvgarEngine.Scanner]::ScanJarsParallel($JarFiles.ToArray())
    foreach ($r in $JarRes) { Register-Hit $r.Severity $r.Type $r.Target $r.Details }
}

Update-UI "Проверка форензики и логов ОС..." 75

$Regex = '(SystemDLC|Cortex|MHub|SS_Cleaner|AveyCleaner|OceanCleaner|ViperCleaner|PrefetchCleaner)'

# DNS
$Dns = ipconfig /displaydns 2>&1 | Out-String
foreach ($d in @("systemdlc", "mhub", "cortex", "vape.gg", "manthe.net", "slinky.gg")) {
    if ($Dns -match $d) { Register-Hit "CRITICAL" "Сетевой след" "ipconfig /displaydns" "Домен чит-сервера: $d" }
}

# Prefetch
if (Test-Path "C:\Windows\Prefetch") {
    $Pf = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue
    if ($Pf.Count -lt 15) { Register-Hit "WARNING" "Тотальная очистка" "C:\Windows\Prefetch" "Папка очищена клинером. Файлов: $($Pf.Count)" }
    $Pf | Where-Object Name -match $Regex | ForEach-Object {
        Register-Hit "CRITICAL" "След чита в Prefetch" $_.FullName "Время запуска: $($_.LastWriteTime)"
    }
}

# BAM
$Bam = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
if (Test-Path $Bam) {
    Get-ChildItem $Bam -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue | Select-Object -Property * | ForEach-Object {
            foreach ($p in $_.PSObject.Properties) {
                if ($p.Name -match $Regex) { Register-Hit "CRITICAL" "След в реестре BAM" $p.Name "ОС зафиксировала запуск" }
            }
        }
    }
}

# USN
$Usn = fsutil usn queryjournal C: 2>&1 | Out-String
if ($Usn -match 'Error|not active|ошиб|активен') { Register-Hit "CRITICAL" "Уничтожение логов файловой системы" "C: USN Journal" "Журнал принудительно отключен" }

Update-UI "Генерация финального отчета..." 100
$Sw.Stop()
Start-Sleep -Seconds 1
Clear-Host

# ----------------- ВЫВОД -----------------
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " SCAN COMPLETED IN $([Math]::Round($Sw.Elapsed.TotalSeconds, 2)) SECONDS" -ForegroundColor White
Write-Host "================================================================================" -ForegroundColor Cyan

if ($Hits.Count -eq 0) {
    Write-Host "`n [STATUS] CLEAN. Чисто, нарушений не найдено.`n" -ForegroundColor Green
} else {
    Write-Host "`n DETECTIONS LOG:`n" -ForegroundColor Red
    foreach ($h in ($Hits | Select-Object -Unique Type, Target, Details)) {
        Write-Host " [${h.Level}] ${h.Type}" -ForegroundColor Red
        Write-Host "  ГДЕ    : $($h.Target)" -ForegroundColor Gray
        Write-Host "  ДЕТАЛИ : $($h.Details)`n" -ForegroundColor DarkGray
    }
}

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " TOTAL HITS: $($Hits.Count)" -ForegroundColor White
Write-Host "================================================================================" -ForegroundColor Cyan

$OutFile = Join-Path $OutputDir "Avgar_Scan_$(Get-Date -Format 'HH-mm-ss').log"
"AVGAR SCAN LOG`nTIME: $(Get-Date)`n`nHITS:`n" + ($Hits | Out-String) | Out-File $OutFile -Encoding UTF8
Write-Host "`n Log saved: $OutFile" -ForegroundColor DarkGray

Read-Host "`nPress Enter to exit..."