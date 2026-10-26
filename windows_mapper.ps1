# Felix Fons Campus Service Mapper for Windows. PowerShell 2.0 compatible.
param([string]$OutDir = '', [switch]$SelfTest)
$ErrorActionPreference = 'Stop'
$warnings = New-Object System.Collections.ArrayList
function Warn([string]$s) { [void]$warnings.Add($s) }
function Safe([object]$v, [int]$limit = 160) {
    if ($null -eq $v) { return '' }
    $s = [regex]::Replace([string]$v, '[\x00-\x1f\x7f]', ' ')
    if ($s.Length -gt $limit) { $s = $s.Substring(0,$limit) }
    return $s.Trim()
}
function JQuote([string]$s) {
    $b = New-Object System.Text.StringBuilder
    [void]$b.Append('"')
    foreach ($ch in $s.ToCharArray()) {
        $n = [int]$ch
        if ($n -eq 34) { [void]$b.Append('\"') }
        elseif ($n -eq 92) { [void]$b.Append('\\') }
        elseif ($n -eq 10) { [void]$b.Append('\n') }
        elseif ($n -eq 13) { [void]$b.Append('\r') }
        elseif ($n -eq 9) { [void]$b.Append('\t') }
        elseif ($n -lt 32) { [void]$b.Append(('\u{0:x4}' -f $n)) }
        else { [void]$b.Append($ch) }
    }
    [void]$b.Append('"')
    return $b.ToString()
}
function JValue([object]$v) {
    if ($null -eq $v) { return 'null' }
    if ($v -is [bool]) { if ($v) { return 'true' } else { return 'false' } }
    if ($v -is [string]) { return (JQuote $v) }
    if ($v -is [System.Collections.IDictionary]) {
        $p = New-Object System.Collections.ArrayList
        foreach ($k in $v.Keys) { [void]$p.Add((JQuote ([string]$k)) + ':' + (JValue $v[$k])) }
        return '{' + [string]::Join(',', [string[]]$p.ToArray()) + '}'
    }
    if ($v -is [System.Collections.IEnumerable]) {
        $p = New-Object System.Collections.ArrayList
        foreach ($item in $v) { [void]$p.Add((JValue $item)) }
        return '[' + [string]::Join(',', [string[]]$p.ToArray()) + ']'
    }
    if ($v -is [ValueType]) { return [System.Convert]::ToString($v,[cultureinfo]::InvariantCulture) }
    return (JQuote ([string]$v))
}
function WriteFile([string]$path,[string]$value) {
    $enc = New-Object System.Text.UTF8Encoding -ArgumentList $false
    [IO.File]::WriteAllText($path,$value,$enc)
}
function HashFile([string]$path) {
    $sha = New-Object Security.Cryptography.SHA256Managed
    $stream = [IO.File]::OpenRead($path)
    try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLowerInvariant() }
    finally { $stream.Close(); $sha.Dispose() }
}
function LockFolder([string]$path) {
    $acl = Get-Acl -LiteralPath $path
    $acl.SetAccessRuleProtection($true,$false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $prop = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $full = [Security.AccessControl.FileSystemRights]::FullControl
    $ids = @([Security.Principal.WindowsIdentity]::GetCurrent().User,
             (New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'),
             (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'))
    foreach ($id in $ids) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($id,$full,$inherit,$prop,$allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $path -AclObject $acl
}
function Wmi([string]$class) {
    try { return @(Get-WmiObject -Class $class -ErrorAction Stop | Select-Object -First 500) }
    catch { Warn ('WMI ' + $class + ' unavailable'); return @() }
}
function Finding([string]$priority,[string]$observed,[string]$risk,[string]$check,[string]$source) {
    return @{priority=$priority;observed=$observed;possible_risk=$risk;verify_before_enable=$check;source=$source}
}
function GetSites() {
    $rows = New-Object System.Collections.ArrayList
    $cmd = Join-Path $env:windir 'System32\inetsrv\appcmd.exe'
    if (-not (Test-Path -LiteralPath $cmd)) { Warn 'IIS appcmd unavailable'; return ,($rows.ToArray()) }
    try {
        foreach ($line in @(& $cmd list site 2>$null | Select-Object -First 500)) {
            if ($line -notmatch '^SITE\s+"([^"]{1,160})"\s+\((.*)\)') { continue }
            $siteName = Safe $Matches[1]; $details = $Matches[2]
            $names = New-Object System.Collections.ArrayList
            $ports = New-Object System.Collections.ArrayList
            $bindings = New-Object System.Collections.ArrayList
            if ($details -match 'bindings:(.*?)(?:,state:|$)') {
                $bindingText = $Matches[1]
                foreach ($part in ($bindingText -split ',')) {
                    if ($part -match '^(https?)/[^:]*:(\d{1,5}):([^,]*)$') {
                        $protocol = $Matches[1]; $port = [int]$Matches[2]; $hostName = Safe $Matches[3]
                        if (-not $ports.Contains($port)) { [void]$ports.Add($port) }
                        if ($hostName -match '^[A-Za-z0-9*_.-]{1,160}$' -and -not $names.Contains($hostName)) { [void]$names.Add($hostName) }
                        [void]$bindings.Add(@{protocol=$protocol;port=$port;host=$hostName})
                    }
                }
            }
            $state = ''
            if ($details -match 'state:([^,)]+)') { $state = Safe $Matches[1] }
            [void]$rows.Add(@{site_name=$siteName;names=$names.ToArray();listen=$ports.ToArray();
                              bindings=$bindings.ToArray();state=$state;routes=@();source='IIS appcmd'})
        }
    } catch { Warn 'IIS site listing failed' }
    return ,($rows.ToArray())
}
function GetListeners([hashtable]$pidNames) {
    $rows = New-Object System.Collections.ArrayList
    try {
        foreach ($line in @(netstat.exe -ano -p tcp 2>$null)) {
            if ($rows.Count -ge 500) { Warn 'TCP listener list truncated'; break }
            if ($line -match '^\s*TCP\s+(\S+)\s+\S+\s+(LISTENING|ПРОСЛУШИВАНИЕ)\s+(\d+)\s*$') {
                $address=$Matches[1]; $pidNum=[int]$Matches[3]
                if ($address -notmatch ':(\d{1,5})$') { continue }
                $port=[int]$Matches[1]
                $bind='specific_interface'
                if ($address -match '^(0\.0\.0\.0:|\[::\]:|\*:)') { $bind='all_interfaces' }
                elseif ($address -match '^(127\.|\[::1\]:)') { $bind='loopback' }
                $proc=''; if ($pidNames.ContainsKey($pidNum)) { $proc=$pidNames[$pidNum] }
                [void]$rows.Add(@{port=$port;bind=$bind;process=$proc})
            }
        }
    } catch { Warn 'TCP listeners unavailable' }
    return ,($rows.ToArray())
}
function GetApps() {
    $rows = New-Object System.Collections.ArrayList
    $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
               'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    foreach ($path in $paths) {
        try {
            foreach ($app in @(Get-ItemProperty $path -ErrorAction Stop)) {
                if ($rows.Count -ge 500) { Warn 'Application list truncated'; break }
                $name = Safe $app.DisplayName
                if ($name -match '(?i)IIS|PHP|Apache|nginx|Node\.js|TrueConf|Bitrix|MySQL|MariaDB|PostgreSQL|SQL Server|Python') {
                    [void]$rows.Add(@{package=$name;version=(Safe $app.DisplayVersion 80)})
                }
            }
        } catch { Warn 'One installed-software registry view unavailable' }
    }
    return ,($rows.ToArray())
}
function GetCerts() {
    $rows = New-Object System.Collections.ArrayList
    try {
        foreach ($cert in @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop | Select-Object -First 500)) {
            $cn=''; if ($cert.Subject -match 'CN=([^,]+)') { $cn=Safe $Matches[1] }
            [void]$rows.Add(@{names=@($cn);not_after=$cert.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')})
        }
    } catch { Warn 'Machine certificate store unavailable' }
    return ,($rows.ToArray())
}

if ($SelfTest) {
    $sample = @{schema=1; platform='windows'; names=@('a.example','x"y');
                enabled=$true; empty=@(); nested=@{port=443; note="line`nnext"}}
    Write-Output (JValue $sample)
    return
}

if (-not $OutDir) {
    $homeBase=$env:LOCALAPPDATA
    if (-not $homeBase) { $homeBase=$env:USERPROFILE }
    if (-not $homeBase) { throw 'No user profile directory available; specify -OutDir' }
    $base=Join-Path $homeBase 'FelixFonsCampusMapper'
    if (-not (Test-Path -LiteralPath $base)) { [void](New-Item -ItemType Directory -Path $base -ErrorAction Stop) }
    $OutDir=Join-Path $base ('campus-report-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
if (Test-Path -LiteralPath $OutDir) { throw 'Output directory already exists' }
[void](New-Item -ItemType Directory -Path $OutDir -ErrorAction Stop)
try { LockFolder $OutDir }
catch { Warn 'Could not restrict output ACL; report saved with inherited folder permissions. Review access before sharing.' }
$os=@(Wmi 'Win32_OperatingSystem' | Select-Object -First 1)[0]
$caption='Windows version unavailable'; $version=''; $build=''; $ubr=0
if ($os) { $caption=Safe $os.Caption; $version=Safe $os.Version 40; $build=Safe $os.BuildNumber 30 }
try { $ubr=[int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR } catch {}
$hostName=Safe $env:COMPUTERNAME
$services=New-Object System.Collections.ArrayList
foreach ($svc in @(Wmi 'Win32_Service')) {
    [void]$services.Add(@{name=(Safe $svc.Name);active=(Safe $svc.State 30).ToLowerInvariant();
                          enabled=(Safe $svc.StartMode 30);pid=[int]$svc.ProcessId})
}
$pidNames=@{}
foreach ($proc in @(Wmi 'Win32_Process')) { $pidNames[[int]$proc.ProcessId]=Safe $proc.Name }
$listeners=GetListeners $pidNames
$sites=GetSites
$apps=GetApps
$hotfixes=New-Object System.Collections.ArrayList
foreach ($fix in @(Wmi 'Win32_QuickFixEngineering')) { if ($fix.HotFixID) { [void]$hotfixes.Add((Safe $fix.HotFixID 30)) } }
$ips=New-Object System.Collections.ArrayList
foreach ($nic in @(Wmi 'Win32_NetworkAdapterConfiguration')) {
    if ($nic.IPEnabled -and $nic.IPAddress) {
        foreach ($ip in $nic.IPAddress) { if ($ip -match '^[0-9a-fA-F.:]+$' -and -not $ips.Contains($ip)) { [void]$ips.Add($ip) } }
    }
}
$disk=''
try {
    $d=@(Wmi 'Win32_LogicalDisk' | Where-Object { $_.DeviceID -eq $env:SystemDrive } | Select-Object -First 1)[0]
    if ($d -and [double]$d.Size -gt 0) { $disk=([string][int](100*(1-[double]$d.FreeSpace/[double]$d.Size)))+'%' }
} catch { Warn 'Disk usage unavailable' }
$eventCounts=@{}
try {
    $eventCounts['system']=@(Get-EventLog -LogName System -After (Get-Date).AddDays(-1) -EntryType Error -Newest 200 -ErrorAction SilentlyContinue).Count
    $eventCounts['application']=@(Get-EventLog -LogName Application -After (Get-Date).AddDays(-1) -EntryType Error -Newest 200 -ErrorAction SilentlyContinue).Count
} catch { Warn 'Event log counts unavailable' }
$firewall=@{}
try {
    $policy=New-Object -ComObject HNetCfg.FwPolicy2
    foreach ($profile in @(1,2,4)) { $firewall[[string]$profile]=[bool]$policy.FirewallEnabled($profile) }
} catch { Warn 'Firewall profile state unavailable' }
$findings=New-Object System.Collections.ArrayList
if ($caption -match 'Server 2008') {
    $lifeUrl='https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2008'
    if ($caption -match '2008 R2') { $lifeUrl='https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2008-r2' }
    [void]$findings.Add((Finding 'критический' ($caption+' '+$version) 'Microsoft support for this Server 2008 release ended.' 'Plan migration; check isolation, access and recovery before temporary use.' $lifeUrl))
}
if ($caption -match 'Windows 10' -and $build -eq '19044' -and $ubr -gt 0 -and $ubr -lt 7807) {
    [void]$findings.Add((Finding 'высокий' ('Windows build 19044.'+$ubr) 'Build predates October 2026 LTSC update; exact missing fixes unknown.' 'Confirm edition, KBs and update source; schedule supported update.' 'https://learn.microsoft.com/en-us/windows/release-health/release-information'))
}
foreach ($app in $apps) {
    if ($app.package -match '(?i)PHP|TrueConf|Bitrix') {
        [void]$findings.Add((Finding 'проверка' ($app.package+' '+$app.version+' installed') 'Registry entry does not identify the active runtime or prove a CVE.' 'Check running process, site binding and vendor fixes.' 'local observation'))
    }
}
foreach ($item in $listeners) {
    if ((@(1433,3306,5432,6379) -contains $item.port) -and $item.bind -eq 'all_interfaces') {
        [void]$findings.Add((Finding 'высокий' ('Data port '+$item.port+' listens on all interfaces') 'External access is unknown.' 'Check firewall, NAT and ACL.' 'local observation'))
    }
}
$report=@{schema=1;platform='windows';collector_version='0.3.0';collected_at=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ');
    host=$hostName;os=($caption+' '+$version);distribution=@{id='windows';pretty_name=$caption};windows_build=$build;windows_ubr=$ubr;
    local_addresses=$ips.ToArray();disk_root_used=$disk;listeners=$listeners;services=$services.ToArray();windows_websites=$sites;
    installed_packages=@{manager='Windows registry';all=$apps;selected=$apps};windows_hotfixes=$hotfixes.ToArray();
    windows_firewall_profiles=$firewall;certificates=(GetCerts);nginx_vhosts=@();apache_vhosts=@();nginx_upstreams=@{};
    php_pools=@();containers=@();tunnels=@();service_unit_files=@();versions_cli_only=@{};
    journal_errors_24h=$eventCounts;journal_categories_24h=@{};backup_indicators=@();security_triage=$findings.ToArray();
    warnings=$warnings.ToArray();not_checked=@('external availability','IIS application routes','account permissions','backup restoration','remote firewall/NAT','raw event messages')}
WriteFile (Join-Path $OutDir 'inventory.private.json') ((JValue $report)+"`n")
$lines=New-Object System.Collections.ArrayList
[void]$lines.Add('FELIX FONS - ПРЕДВАРИТЕЛЬНАЯ КАРТА WINDOWS-СЕРВИСОВ')
[void]$lines.Add(('Узел: '+$hostName+' | ОС: '+$caption+' '+$version+' | Сборка: '+$build+'.'+$ubr))
[void]$lines.Add('Локальная проверка без изменений. Доступность извне и факт взлома не проверялись.')
[void]$lines.Add('САЙТЫ IIS')
foreach ($site in $sites) { [void]$lines.Add(($site.site_name+' | '+$site.state+' | hosts='+[string]::Join(',', [string[]]$site.names)+' | ports='+[string]::Join(',', [string[]]$site.listen))) }
if ($sites.Count -eq 0) { [void]$lines.Add('Сайты IIS не найдены или недоступны; другой веб-сервер возможен.') }
[void]$lines.Add('СЛУШАЮЩИЕ TCP-ПОРТЫ (IP И PID ОПУЩЕНЫ)')
foreach ($item in $listeners) { [void]$lines.Add(([string]$item.port+' | '+$item.bind+' | '+$item.process)) }
[void]$lines.Add('УСТАНОВЛЕННЫЕ ПРИЛОЖЕНИЯ ПО ВЫБОРКЕ')
foreach ($app in $apps) { [void]$lines.Add(($app.package+' | '+$app.version)) }
[void]$lines.Add('ПРИОРИТЕТЫ: ФАКТ | ВОЗМОЖНЫЙ РИСК | ЧТО ПРОВЕРИТЬ')
foreach ($f in $findings) { [void]$lines.Add(($f.priority+' | '+$f.observed+' | '+$f.possible_risk+' | '+$f.verify_before_enable)) }
[void]$lines.Add('ПРОБЕЛЫ В СБОРЕ')
foreach ($w in $warnings) { [void]$lines.Add(('- '+$w)) }
[void]$lines.Add(('Профили брандмауэра: '+(JValue $firewall)+'; ошибки журналов за сутки (до 200/журнал): '+(JValue $eventCounts)))
[void]$lines.Add(('Номеров обновлений в закрытом JSON: '+$hotfixes.Count+'. Это не подтверждение полноты исправлений.'))
[void]$lines.Add('До включения каждого сервиса проверить вход, роли, данные, восстановление из копии, TLS и бюллетени поставщика.')
[void]$lines.Add('Felix Fons | https://felixfons.ru | +7 917 410-87-48')
WriteFile (Join-Path $OutDir 'summary.txt') ([string]::Join("`r`n",[string[]]$lines.ToArray())+"`r`n")
$cards=New-Object System.Collections.ArrayList
[void]$cards.Add('FELIX FONS - КАРТОЧКИ WINDOWS-СЕРВИСОВ')
foreach ($site in $sites) {
    [void]$cards.Add(('Сайт: '+$site.site_name+' | имена: '+[string]::Join(',', [string[]]$site.names)))
    [void]$cards.Add('[ ] Установлены владелец, назначение и все привязки сайта.')
    [void]$cards.Add('[ ] Проверены работающий процесс, приложение, библиотеки и исправления.')
    [void]$cards.Add('[ ] Проверены вход, роли и доступ администраторов.')
    [void]$cards.Add('[ ] Испытано восстановление из копии и TLS в ответе клиенту.')
    [void]$cards.Add('[ ] Проверены сценарии пользователя, наблюдение и откат.')
    [void]$cards.Add('Решение о включении: НЕ ПРИНЯТО')
    [void]$cards.Add('')
}
WriteFile (Join-Path $OutDir 'service_cards.txt') ([string]::Join("`r`n",[string[]]$cards.ToArray())+"`r`n")
$manifest=New-Object System.Collections.ArrayList
foreach ($f in @('inventory.private.json','summary.txt','service_cards.txt')) { [void]$manifest.Add(((HashFile (Join-Path $OutDir $f))+'  '+$f)) }
WriteFile (Join-Path $OutDir 'manifest.sha256') ([string]::Join("`n",[string[]]$manifest.ToArray())+"`n")
Write-Host ('Report saved to: '+$OutDir)

