$ErrorActionPreference = "SilentlyContinue"
Clear-Host

Write-Host "=================================================================" -ForegroundColor Yellow
Write-Host "   ПОЛНОЕ ГЛУБОКОЕ СКАНИРОВАНИЕ ПК НА СЛЕДЫ SYSTEM DLC / ИНЖЕКТОВ" -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Yellow

# 1. ПРОВЕРКА ПРОЦЕССОВ ИГРЫ И СКРЫТЫХ МОДУЛЕЙ В ОЗУ
Write-Host "`n[1/7] Анализ процессов Minecraft и загруженных библиотек..." -ForegroundColor Cyan
$mc = Get-Process -Name "javaw", "java"
if ($mc) {
    foreach ($p in $mc) {
        Write-Host "  Процесс: $($p.Name) | PID: $($p.Id) | Запуск: $($p.StartTime) | Потоков: $($p.Threads.Count)" -ForegroundColor Green
        $mods = $p.Modules | Where-Object {
            $_.FileName -notmatch "Windows\\System32|Windows\\SysWOW64|Java|jdk|jre|NVIDIA|AMD|Intel|OpenAL|lwjgl|glfw|jemalloc|ucrtbase"
        }
        if ($mods) {
            Write-Host "  [!] ОБНАРУЖЕНЫ СТОРОННИЕ DLL В ПАМЯТИ ИГРЫ:" -ForegroundColor Red
            $mods | Select-Object ModuleName, FileName | Format-Table -AutoSize
        } else {
            Write-Host "  Сторонних DLL с диска нет." -ForegroundColor Gray
        }
    }
} else {
    Write-Host "  Игра сейчас не запущена." -ForegroundColor Gray
}

# 2. ПРОВЕРКА ВСЕХ НЕСТАНДАРТНЫХ ПРОЦЕССОВ В ПАМЯТИ ПК
Write-Host "`n[2/7] Проверка активных процессов вне системных папок..." -ForegroundColor Cyan
$suspProcs = Get-CimInstance Win32_Process | Where-Object {
    $_.ExecutablePath -and
    $_.ExecutablePath -notmatch "C:\\Windows|C:\\Program Files|C:\\ProgramData|AppData\\Local\\Programs|Discord|Steam|Telegram|Yandex|Google"
}
if ($suspProcs) {
    $suspProcs | Select-Object Name, ProcessId, ExecutablePath | Format-Table -AutoSize
} else {
    Write-Host "  Подозрительных активных процессов не найдено." -ForegroundColor Gray
}

# 3. ПРОВЕРКА РЕЕСТРА ЗАПУСКОВ: BAM + RUNMRU (WIN+R) + USERASSIST
Write-Host "`n[3/7] Проверка реестра запусков (BAM и история Win+R)..." -ForegroundColor Cyan
# История Win+R (RunMRU)
$runMru = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
if ($runMru) {
    $runMru.PSObject.Properties | Where-Object { $_.Name -match "^[a-z]$" } | ForEach-Object {
        Write-Host "  [Win+R]: $($_.Value)" -ForegroundColor White
    }
}
# BAM (Все запущенные EXE за сессию, даже удаленные)
$bamPaths = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*", "HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*")
foreach ($bp in $bamPaths) {
    Get-ItemProperty -Path $bp | ForEach-Object {
        $_.PSObject.Properties | Where-Object {
            $_.Name -match "\\Device\\HarddiskVolume" -and
            $_.Name -notmatch "Windows\\System32|Windows\\SysWOW64|Program Files|NVIDIA|Discord|Steam|Telegram|Yandex|Chrome|Edge"
        } | ForEach-Object {
            $clean = $_.Name -replace "\\Device\\HarddiskVolume\d+", "C:"
            Write-Host "  [BAM Запуск]: $clean" -ForegroundColor White
        }
    }
}

# 4. ПРОВЕРКА PREFETCH (СЛЕДЫ ЗАПУСКА ЗА ПОСЛЕДНИЕ 48 ЧАСОВ)
Write-Host "`n[4/7] Проверка Prefetch (несистемные запуски за 48 часов)..." -ForegroundColor Cyan
$pf = Get-ChildItem -Path "C:\Windows\Prefetch\*.pf" | Where-Object {
    $_.LastWriteTime -gt (Get-Date).AddHours(-48) -and
    $_.Name -notmatch "SVCHOST|CONHOST|RUNDLL32|CMD|POWERSHELL|CHROME|DISCORD|STEAM|EXPLORER|SEARCH|RUNTIME|TASKMGR|DLLHOST|NOTEPAD|MSEDGE|BACKGROUND|APPLICATIONFRAME|CONSENT|SMART|COMPATTEL|WMI|SIHOST|CTFMON|AUDIODG|SYSTEMSETTINGS"
} | Sort-Object LastWriteTime -Descending
if ($pf) {
    $pf | Select-Object Name, LastWriteTime | Format-Table -AutoSize
} else {
    Write-Host "  Подозрительных Prefetch-записей за 48 часов нет." -ForegroundColor Gray
}

# 5. ПРОВЕРКА СЕТИ И DNS-КЭША
Write-Host "`n[5/7] Проверка DNS-кэша на домены читов/лоадеров..." -ForegroundColor Cyan
$dns = Get-DnsClientCache | Where-Object {
    $_.Entry -match "system|dlc|cheat|auth|loader|unhook|destruct|bypass|inject" -and
    $_.Entry -notmatch "microsoft|windows|google|yandex|vk|mail|steam|discord|mojang|minecraft"
}
if ($dns) {
    Write-Host "  [!] НАЙДЕНЫ ПОДОЗРИТЕЛЬНЫЕ ДОМЕНЫ:" -ForegroundColor Red
    $dns | Select-Object Entry, Data | Format-Table -AutoSize
} else {
    Write-Host "  DNS-кэш чист." -ForegroundColor Gray
}

# 6. ПРОВЕРКА ИСТОРИИ КОМАНД (С ФИЛЬТРОМ ВАШИХ ПРОВЕРОК)
Write-Host "`n[6/7] Проверка истории консоли (очищенная от прошлых проверок)..." -ForegroundColor Cyan
$hist = (Get-PSReadLineOption).HistorySavePath
if (Test-Path $hist) {
    $cleanHist = Get-Content $hist | Where-Object {
        $_ -match "system|dlc|python|py |pip |inject|pymem|\.py|curl|wget|iwr|invoke" -and
        $_ -notmatch "Get-DnsClientCache|HarddiskVolume|Get-CimInstance|Get-WinEvent|HistorySavePath|Write-Host|Clear-Host|ErrorActionPreference|Get-ChildItem|Select-String"
    }
    if ($cleanHist) {
        Write-Host "  [!] Найдены сторонние команды:" -ForegroundColor Red
        $cleanHist | ForEach-Object { Write-Host "    -> $_" -ForegroundColor White }
    } else {
        Write-Host "  Сторонних команд в истории PowerShell нет." -ForegroundColor Gray
    }
}

# 7. ПОЛНОЕ СКАНИРОВАНИЕ ВСЕХ ДИСКОВ ПК (ФАЙЛЫ, КОНФИГИ, ЛОГИ, КЭШ)
Write-Host "`n[7/7] Глубокое сканирование всех локальных дисков (ожидайте)..." -ForegroundColor Cyan
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 }
$foundAny = $false
foreach ($d in $drives) {
    Write-Host "  Сканируется диск $($d.Root)..." -ForegroundColor DarkGray
    Get-ChildItem -Path $d.Root -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {
        $_.FullName -notmatch "\\Windows\\WinSxS|\\Windows\\servicing|\\Program Files\\WindowsApps" -and
        $_.Name -match "systemdlc|system_dlc|sysdlc|systemclient"
    } | ForEach-Object {
        $foundAny = $true
        Write-Host "  [!] НАЙДЕН ФАЙЛ/ПАПКА: $($_.FullName) (Изменен: $($_.LastWriteTime))" -ForegroundColor Red
    }
}
if (-not $foundAny) {
    Write-Host "  На всех дисках файлов с именами SystemDLC / SystemClient не обнаружено." -ForegroundColor Gray
}

Write-Host "`n=================================================================" -ForegroundColor Yellow
Write-Host "   СКАНИРОВАНИЕ ПОЛНОСТЬЮ ЗАВЕРШЕНО!" -ForegroundColor Yellow
Write-Host "=================================================================" -ForegroundColor Yellow
