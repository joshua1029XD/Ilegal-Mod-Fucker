<#
.SYNOPSIS
  Ilegal Fucker - Screenshare Scanner (PowerShell) - revision de instancias de Minecraft Java. SOLO LECTURA.

.DESCRIPTION
  Detecta mods de hacks/clientes, ofuscacion, funciones de totem, herramientas de evasion
  (self-destruct, anti-SS, Java Agents, revision de procesos), suplantacion de mods conocidos,
  mods prohibidos por reglas, jars disfrazados, logs borrados y hashes (lista blanca / negra).
  Por defecto compara SHA-512 contra la API publica de Modrinth; no envia archivos ni contenido.
  Usa -NoModrinth para un analisis completamente local.

.EXAMPLE
  irm https://raw.githubusercontent.com/joshua1029XD/Ilegal-Mod-Fucker/main/IlegalFuckerv1.8.ps1 | iex
  (un solo comando; pregunta la ruta y con ENTER usa %APPDATA%\.minecraft)
.EXAMPLE
  iex "& { $(irm https://raw.githubusercontent.com/joshua1029XD/Ilegal-Mod-Fucker/main/IlegalFuckerv1.8.ps1) } -All -Out $env:USERPROFILE\Desktop\reporte.txt"
.EXAMPLE
  .\IlegalFucker.ps1 -Path "C:\ruta\instancia"       # solo esa instancia
  .\IlegalFucker.ps1 -MakeWhitelist whitelist.json     # guarda los hashes de los mods actuales
#>
[CmdletBinding()]
param(
    [string]$Path,
    [string]$Whitelist,
    [string]$BadHashes,
    [string]$BannedIds,
    [string]$MakeWhitelist,
    [double]$RecentHours = 0,
    [switch]$All,
    [string]$Out,
    [switch]$NoModrinth
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$VERSION = '1.8'

# ======================================================== FIRMAS (editables)
$STRONG = @('meteordevelopment','meteor-client','meteorclient','wurstclient','wurst-client','net/wurstclient',
  'liquidbounce','ccbluex','aristois','futureclient','bleachhack','rusherhack','thunderhack','kamiblue','salhack',
  'huzuni','novoline','inertiaclient','impactclient','konas','3arthh4ck','gamesense','coffeeclient','skillclient',
  'tenacityclient','astolfoclient','pandaware','dreamclient','sigmaclient','vapeclient','vape.gg','lambda-client',
  'lambdaclient','abyssclient','xenon-client','freecam-hack','killaura','hnt3r','.hnt3_sig')

$WEAK = @('killaura','aimassist','triggerbot','autoclicker','scaffold','nofall','xray','freecam','crystalaura',
  'anchoraura','fakelag','backtrack','hitboxes','nuker','antiknockback','autoarmor','fastplace','noslow',
  'reachhack','autocrystal','tpaura','elytrafly','airjump','flyhack','speedhack')

$EVASION = @('selfdestruct','self-destruct','self_destruct','antiscreenshare','anti-screenshare','anti_screenshare',
  'anti-ss','anti_ss','ssbypass','ss-bypass','ss_bypass','hidemodlist','hidefrommodlist',
  'tracecleaner','logcleaner','stringcleaner','jarspoof','modspoof','antianalyz','anti-analyz','anticheatbypass',
  'acbypass','anticheat-bypass','antidetect','anti-detect','antidetection','bypassss','ss-evader','ssevader','ss_evader')

# totem + palabra de hack (evita marcar mods que solo usan el Totem de la Inmortalidad)
$TOTEM_RE = '(auto|hover|swap|refill|legit|bypass|offhand|inventory|inv)[ _\-]?totem|totem[ _\-]?(hit|swap|refill|bypass|hover|auto|legit|pop|dtap|offhand)'

# APIs para revisar procesos / ejecutar comandos (esconderse al abrir una SS tool)
$API_PROC_STRONG = @('tasklist','taskkill','powershell','cmd.exe')
$API_PROC_WEAK   = @('java/lang/instrument','com/sun/tools/attach','wmic','processhandle')
$API_PROC = $API_PROC_STRONG + $API_PROC_WEAK
# APIs genericas: solo cuentan si aparecen 4 o mas juntas
$API_GEN = @('defineclass','sun/misc/unsafe','loadlibrary','urlclassloader','javax/crypto/cipher','deleteonexit','java/lang/processbuilder')
$INJECTION_KEYS = @('java/lang/instrument','com/sun/tools/attach','virtualalloc','writeprocessmemory','createremotethread',
  'openprocess','loadlibrarya','loadlibraryw','injectdll','dllinject','jvmti','setwindows hook','process_vm_writev',
  'ptrace','createprocessa','createprocessw','addvectoredexceptionhandler')
$RESIDUE_WORDS = @('meteor','wurst','liquidbounce','aristois','rusherhack','vape','inertia','huzuni','konas',
  'impact','futureclient','bleachhack','tenacity','autototem','triggerbot','selfdestruct','self-destruct',
  'antiscreenshare','ssbypass','inject','injected','cheatclient','ghostclient','jarmod','dllinject')

$NATIVE_EXT     = @('.dll','.exe','.bat','.cmd','.ps1','.vbs')
$SUSPICIOUS_EXT = @('.exe','.dll','.bat','.cmd','.ps1','.vbs','.scr','.msi','.so','.dylib')
$AGENT_KEYS     = @('premain-class','agent-class','launcher-agent-class','can-retransform-classes')

# Huellas de COMPORTAMIENTO: referencias al codigo del juego que no se pueden renombrar aunque el mod
# cambie de nombre/paquete/id (un "bypass" por renombrado). Cada grupo = alternativas (nombres intermediary,
# mojmap o yarn); la familia se detecta si TODOS los grupos tienen al menos una coincidencia.
$FAMILIES = @(
  @{ name = 'NoInputLag / FastPlace / NoBreakDelay'; why = 'modifica los delays de click derecho y de minado (rightClickDelay + destroyDelay)'
     groups = @(@('field_1752','rightclickdelay','itemusecooldown'), @('field_3716','destroydelay','blockbreakingcooldown')) },
  @{ name = 'NoJumpDelay'; why = 'toca el contador de salto de LivingEntity (jumpingCooldown) en cada tick'
     groups = @(@('field_6228','jumpingcooldown','nojumpdelay'), @('method_5773')) },
  @{ name = 'FastTotem / TotemUtils'; why = 'hace clicks de slot (clickSlot) dentro de onSlotClick y referencia el Totem de la Inmortalidad'
     groups = @(@('minecraft:totem_of_undying','field_8288'), @('method_7593','onslotclick'), @('method_2906','clickslot')) }
  @{ name = 'AutoTotem'; why = 'automatiza el movimiento/equipamiento del Totem de la Inmortalidad hacia la mano secundaria'
     groups = @(@('minecraft:totem_of_undying','totemofundying','field_8288'), @('offhand','off_hand','handoff','secondaryhand'), @('swap','clickslot','onslotclick','inventoryclick','autototem')) }
  @{ name = 'Attack Through Grass'; why = 'altera la comprobacion de bloqueo por hierba o la seleccion de objetivo/raycast durante un ataque'
     groups = @(@('attackthroughgrass','attack_through_grass','throughgrass','grassattack'), @('raycast','ray_trace','raytrace','crosshairtarget','gettargetedentity')) }
  @{ name = 'Accurate Block Placement'; why = 'fuerza una colocacion precisa mediante rotacion, yaw/pitch o seleccion de cara del bloque'
     groups = @(@('accurateblockplacement','accurate_block_placement','accurateplacement'), @('blockplacement','placeblock','tryplace','rightclickblock'), @('yaw','pitch','rotation','facing','blockface')) }
  @{ name = 'Firework Rocket Key'; why = 'vincula una tecla para usar automaticamente cohetes de fuegos artificiales, normalmente durante el vuelo'
     groups = @(@('firerocketkey','fireworkrocketkey','firework_rocket_key','rocketkey'), @('firework_rocket','fireworkrocket','minecraft:firework_rocket'), @('keybind','keymapping','keybinding','ispressed','waspressed')) }
  @{ name = 'Hotbar Refill / Refill'; why = 'rellena automaticamente huecos o stacks de la hotbar desde el inventario'
     groups = @(@('refill','refillear','hotbarrefill','hotbar_refill','inventoryrefill'), @('hotbar','hot_bar','hotbarslot'), @('clickslot','quickmove','inventoryclick','moveslot','swap')) }
  @{ name = 'Hotbar AutoTotem'; why = 'automatiza el uso o intercambio del Totem desde la hotbar, una funcion de ventaja en PvP'
     groups = @(@('minecraft:totem_of_undying','totemofundying','autototem','totemutils'), @('hotbar','hot_bar','hotbarslot'), @('swap','clickslot','quickmove','inventoryclick')) }
  @{ name = 'Inventory Totem'; why = 'mueve o equipa automaticamente un Totem desde el inventario durante el combate'
     groups = @(@('minecraft:totem_of_undying','totemofundying','inventorytotem','totemutils'), @('inventory','container','slot'), @('clickslot','quickmove','swap','onslotclick')) }
  @{ name = 'TriggerBot'; why = 'ataca automaticamente al detectar una entidad valida bajo la mira o el crosshair'
     groups = @(@('triggerbot','trigger_bot','autotrigger'), @('attack','attackentity','attacktarget','leftclick'), @('crosshairtarget','gettargetedentity','raycast','raytrace','tick')) }
)
$fpList = New-Object System.Collections.ArrayList
foreach ($fam in $FAMILIES) { foreach ($grp in $fam.groups) { foreach ($tk in $grp) { [void]$fpList.Add($tk) } } }

# Hashes de mods ya identificados (da igual como se llame el archivo)
$KNOWN_HASHES = @{
  '74fc6fa1b98246368ed2502836ab851b7e41d1d79d2cb68b18e3dbc3e371af51' = 'NoInputLagTickRate (mod prohibido)'
  '766d1f2f5f7bdb71e907a8eca2140ae520ffb175a085810f4f42bc982bda59a1' = 'SimplyNoJumpDelay (mod prohibido)'
  'e8c8c08635fcf7bf3c4bfc45df98e942d8adcbc38f5f20d568f557e3423e7b27' = 'fast-totem (mod prohibido)'
  '5531083502a3cfb06898d56a1cfebfca88cc8d10c897e39e1e402febf181e6f0' = 'TotemUtils = fast totem (mod prohibido)'
  'd4e06b44c700f10f5896048594833e7da281de5055158b68f6ef55e69f461df3' = 'FALSO Krypton = cheat client Hunter'
}

# Mods que no son hacks por codigo pero que muchos servers prohiben. EDITA segun tus reglas (o -BannedIds archivo.json)
$BANNED_MODS = @{
  'fast-totem'         = 'Equipa el totem en la mano secundaria con shift+click (ventaja en PvP)'
  'totemutils'         = 'Quick-move/slot click para mover el totem rapido (ventaja en PvP)'
  'simplynojumpdelay'  = 'Quita el delay de salto (NoJumpDelay)'
  'noinputlagtickrate' = 'Procesa input/minado en el render loop, fuera del tick (ventaja de input)'
}

# Mods conocidos y su paquete Java real (para detectar suplantacion)
$LEGIT_PKGS = @{
  'krypton'         = @('me/steinborn/krypton')
  'sodium'          = @('net/caffeinemc/','me/jellysquid/mods/sodium')
  'lithium'         = @('net/caffeinemc/','me/jellysquid/mods/lithium')
  'iris'            = @('net/irisshaders/','net/coderbot/iris')
  'immediatelyfast' = @('net/raphimc/immediatelyfast')
  'modernfix'       = @('org/embeddedt/modernfix')
}

$RESERVED_WIN = @('con','prn','aux','nul','clock$') + @(1..9 | ForEach-Object { "com$_" }) + @(1..9 | ForEach-Object { "lpt$_" })
$BAD_MOD_IDS  = @('meteor-client','wurst','wurst-client','liquidbounce','aristois','bleachhack','rusherhack',
  'thunderhack','kamiblue','salhack','future','impact','konas')
$CLIENT_DIRS  = @('.wurst','wurst','meteor-client','liquidbounce','LiquidBounce','Impact','future','BleachHack',
  'rusherhack','Aristois','thunderhack','kamiblue','Vape','vape','inertia','huzuni','salhack','konas','lambda')
$CLIENT_VERSION_WORDS = @('wurst','meteor','liquidbounce','impact','aristois','bleach','rusher','future','vape','thunder')

$MAX_ENTRY = 8MB
$MAX_DEPTH = 2

# ======================================================== UTILIDADES
function New-AltRegex([string[]]$words) {
    $alt = ($words | ForEach-Object { [regex]::Escape($_) }) -join '|'
    return New-Object System.Text.RegularExpressions.Regex($alt, [System.Text.RegularExpressions.RegexOptions]::Compiled)
}
$rxStrong   = New-AltRegex $STRONG
$rxWeak     = New-AltRegex $WEAK
$rxEvasion  = New-Object System.Text.RegularExpressions.Regex((($EVASION | ForEach-Object { [regex]::Escape($_) }) -join '|') + '|(?<![a-z])antiss', [System.Text.RegularExpressions.RegexOptions]::Compiled)
$rxApiProc  = New-AltRegex $API_PROC
$rxApiGen   = New-AltRegex $API_GEN
$rxInjection = New-AltRegex $INJECTION_KEYS
$rxResidue = New-AltRegex $RESIDUE_WORDS
$rxTotem    = New-Object System.Text.RegularExpressions.Regex($TOTEM_RE, [System.Text.RegularExpressions.RegexOptions]::Compiled)
$latin1     = [System.Text.Encoding]::GetEncoding(28591)   # bytes 1:1 a texto, para buscar strings en .class

$rxFp = New-Object System.Text.RegularExpressions.Regex(('(?:' + (($fpList | Sort-Object -Unique | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')(?![0-9])'), [System.Text.RegularExpressions.RegexOptions]::Compiled)

function Get-Distinct($rx, [string]$text) {
    $set = @{}
    foreach ($m in $rx.Matches($text)) { $set[$m.Value] = $true }
    return @($set.Keys)
}

function Norm-Id($x) { return (([string]$x).ToLower() -replace '[^a-z0-9]', '') }

function Get-Level([int]$score) {
    if ($score -ge 10) { return 'ALTO' }
    if ($score -ge 4)  { return 'MEDIO' }
    if ($score -ge 1)  { return 'BAJO' }
    return 'OK'
}

$script:lines = New-Object System.Collections.ArrayList
$levelColor = @{ 'ALTO' = 'Red'; 'MEDIO' = 'Yellow'; 'BAJO' = 'Cyan'; 'OK' = 'Green' }
function Say([string]$text, [string]$lv = '') {
    [void]$script:lines.Add($text)
    if ($lv -and $levelColor.ContainsKey($lv)) { Write-Host $text -ForegroundColor $levelColor[$lv] }
    else { Write-Host $text }
}

function Say-Section([string]$title) {
    Say ''
    Say ('=' * 72)
    Say ("  $title") 'MEDIO'
    Say ('=' * 72)
}

function Show-ScanProgress([int]$current, [int]$total, [string]$name) {
    $pct = [int](100 * $current / [Math]::Max(1, $total))
    if ($script:lastProgressPct -eq $pct -and $current -lt $total) { return }
    $script:lastProgressPct = $pct
    $width = 24
    $filled = [int]($width * $pct / 100)
    $bar = ('#' * $filled) + ('.' * ($width - $filled))
    $text = "  Analizando mods  [$bar] $pct%  |  $current/$total  |  $name"
    Write-Host ("`r" + $text.PadRight(120)) -NoNewline -ForegroundColor Cyan
}

function Get-EntryBytes($entry) {
    $st = $entry.Open()
    try {
        $ms = New-Object System.IO.MemoryStream
        $st.CopyTo($ms)
        return , $ms.ToArray()
    } finally { $st.Dispose() }
}

function Get-EntryText($zip, [string]$name) {
    $e = $zip.GetEntry($name)
    if ($null -eq $e) { return $null }
    try { return [System.Text.Encoding]::UTF8.GetString((Get-EntryBytes $e)).TrimStart([char]0xFEFF) } catch { return $null }
}

function New-Info {
    return @{
        ids = New-Object 'System.Collections.Generic.HashSet[string]'
        ids0 = New-Object 'System.Collections.Generic.HashSet[string]'
        names = New-Object 'System.Collections.Generic.HashSet[string]'
        strong = New-Object 'System.Collections.Generic.HashSet[string]'
        weak = New-Object 'System.Collections.Generic.HashSet[string]'
        totem_names = New-Object 'System.Collections.Generic.HashSet[string]'
        totem_content = New-Object 'System.Collections.Generic.HashSet[string]'
        evasion = New-Object 'System.Collections.Generic.HashSet[string]'
        reserved = New-Object 'System.Collections.Generic.HashSet[string]'
        api_proc = New-Object 'System.Collections.Generic.HashSet[string]'
        api_gen = New-Object 'System.Collections.Generic.HashSet[string]'
        natives = New-Object 'System.Collections.Generic.HashSet[string]'
        agent = New-Object 'System.Collections.Generic.HashSet[string]'
        fp = New-Object 'System.Collections.Generic.HashSet[string]'
        injection = New-Object 'System.Collections.Generic.HashSet[string]'
        modrinth_urls = New-Object 'System.Collections.Generic.HashSet[string]'
        nested = New-Object System.Collections.ArrayList
        labels = New-Object System.Collections.ArrayList
        notes = New-Object System.Collections.ArrayList
        names_list = @()
        metaFound = $false
        classes = 0; short = 0; confusing = 0; nonascii = 0; single_pkg = 0
    }
}

# ======================================================== METADATOS
function Read-Metadata($zip, $info) {
    $t = Get-EntryText $zip 'fabric.mod.json'
    if ($null -ne $t) {
        $info.metaFound = $true
        try {
            $j = $t | ConvertFrom-Json
            [void]$info.ids.Add(([string]$j.id).ToLower())
            [void]$info.names.Add(([string]$j.name).ToLower())
            [void]$info.labels.Add("fabric:$($j.id)@$($j.version)")
        } catch { [void]$info.notes.Add('fabric.mod.json ilegible/corrupto') }
    }
    $t = Get-EntryText $zip 'quilt.mod.json'
    if ($null -ne $t) {
        $info.metaFound = $true
        try {
            $j = $t | ConvertFrom-Json
            [void]$info.ids.Add(([string]$j.quilt_loader.id).ToLower())
            [void]$info.labels.Add("quilt:$($j.quilt_loader.id)@$($j.quilt_loader.version)")
        } catch { [void]$info.notes.Add('quilt.mod.json ilegible/corrupto') }
    }
    foreach ($toml in @('META-INF/mods.toml', 'META-INF/neoforge.mods.toml')) {
        $t = Get-EntryText $zip $toml
        if ($null -ne $t) {
            $info.metaFound = $true
            foreach ($m in [regex]::Matches($t, 'modId\s*=\s*"([^"]+)"')) { [void]$info.ids.Add($m.Groups[1].Value.ToLower()) }
            foreach ($m in [regex]::Matches($t, 'displayName\s*=\s*"([^"]+)"')) { [void]$info.names.Add($m.Groups[1].Value.ToLower()) }
            [void]$info.labels.Add("forge:" + (($info.ids | Select-Object -First 3) -join ','))
        }
    }
    $t = Get-EntryText $zip 'mcmod.info'
    if ($null -ne $t) {
        $info.metaFound = $true
        try {
            $j = $t | ConvertFrom-Json
            $items = $j
            if ($j.modList) { $items = $j.modList }
            foreach ($it in @($items)) {
                if ($it.modid) { [void]$info.ids.Add(([string]$it.modid).ToLower()) }
                if ($it.name)  { [void]$info.names.Add(([string]$it.name).ToLower()) }
            }
        } catch { [void]$info.notes.Add('mcmod.info ilegible') }
    }
}

# ======================================================== ANALISIS DE UN ZIP/JAR
function Scan-Zip($zip, $info, [int]$depth, [string]$prefix) {
    $entries = @($zip.Entries)
    $names = @($entries | ForEach-Object { $_.FullName })

    if ($depth -eq 0) {
        Read-Metadata $zip $info
        foreach ($i in $info.ids) { [void]$info.ids0.Add($i) }
        $info.names_list = $names
        foreach ($meta in @('fabric.mod.json','quilt.mod.json','mcmod.info','META-INF/mods.toml','META-INF/neoforge.mods.toml')) {
            $me = $zip.GetEntry($meta)
            if ($null -eq $me) { continue }
            try {
                $mt = [System.Text.Encoding]::UTF8.GetString((Get-EntryBytes $me)).ToLowerInvariant()
                foreach ($m in [regex]::Matches($mt, 'https?://(?:www\.)?modrinth\.com/(?:mod|project)/[^"''\s<>]+')) {
                    [void]$info.modrinth_urls.Add($m.Value.TrimEnd('.', ',', ')', ']', ';'))
                }
            } catch {}
        }
    } else {
        $sub = New-Info
        Read-Metadata $zip $sub
        foreach ($i in $sub.ids)   { [void]$info.ids.Add($i) }
        foreach ($i in $sub.names) { [void]$info.names.Add($i) }
    }

    foreach ($e in $entries) {
        $n = $e.FullName
        if ($n.EndsWith('/')) { continue }
        $low  = $n.ToLowerInvariant()
        $slash = $n.LastIndexOf('/')
        $leafOrig = $n.Substring($slash + 1)
        $leaf = $leafOrig.ToLowerInvariant()
        $stem = $leaf.Split('.')[0]

        if ($RESERVED_WIN -contains $stem) { [void]$info.reserved.Add($prefix + $n) }

        foreach ($kw in (Get-Distinct $rxStrong  $low)) { [void]$info.strong.Add("$prefix$n -> '$kw'") }
        foreach ($kw in (Get-Distinct $rxWeak    $low)) { [void]$info.weak.Add($kw) }
        foreach ($kw in (Get-Distinct $rxEvasion $low)) { [void]$info.evasion.Add("$prefix$n -> '$kw'") }
        $tm = $rxTotem.Match($low)
        if ($tm.Success) { [void]$info.totem_names.Add("$prefix$n -> '$($tm.Value)'") }

        foreach ($x in $NATIVE_EXT) { if ($low.EndsWith($x)) { [void]$info.natives.Add($prefix + $n); break } }

        if ($depth -eq 0 -and $n.ToUpperInvariant() -eq 'META-INF/MANIFEST.MF') {
            $mf = Get-EntryText $zip $n
            if ($null -ne $mf) {
                $mfl = $mf.ToLowerInvariant()
                foreach ($k in $AGENT_KEYS) { if ($mfl.Contains($k)) { [void]$info.agent.Add("$prefix$k") } }
            }
        }

        if ($low.EndsWith('.class')) {
            $info.classes++
            $base = $leafOrig.Substring(0, $leafOrig.Length - 6).Split('$')[0]
            if ($base.Length -le 2) { $info.short++ }
            if ($base -cmatch '^[Il1O0_]{3,}$') { $info.confusing++ }
            if ($n -match '[^\x00-\x7F]') { $info.nonascii++ }
            $parts = $n.Split('/')
            if ($parts.Length -ge 3) {
                $dirs = $parts[0..($parts.Length - 2)]
                if (-not ($dirs | Where-Object { $_.Length -gt 2 })) { $info.single_pkg++ }
            }
            try {
                if ($e.Length -le $MAX_ENTRY) {
                    $text = $latin1.GetString((Get-EntryBytes $e)).ToLowerInvariant()
                    foreach ($kw in (Get-Distinct $rxStrong  $text)) { [void]$info.strong.Add("$prefix$n (contenido) -> '$kw'") }
                    foreach ($kw in (Get-Distinct $rxWeak    $text)) { [void]$info.weak.Add($kw) }
                    foreach ($kw in (Get-Distinct $rxEvasion $text)) { [void]$info.evasion.Add("$prefix$n (contenido) -> '$kw'") }
                    $tm = $rxTotem.Match($text)
                    if ($tm.Success) { [void]$info.totem_content.Add("$prefix$n (contenido) -> '$($tm.Value)'") }
                    foreach ($kw in (Get-Distinct $rxApiProc $text)) { [void]$info.api_proc.Add($kw) }
                    foreach ($kw in (Get-Distinct $rxApiGen  $text)) { [void]$info.api_gen.Add($kw) }
                    foreach ($kw in (Get-Distinct $rxInjection $text)) { [void]$info.injection.Add($kw) }
                    foreach ($kw in (Get-Distinct $rxFp $text)) { [void]$info.fp.Add($kw) }
                }
            } catch {}
        }
        elseif ($low.EndsWith('.json') -and $e.Length -le 2MB) {
            try {
                $jt = [System.Text.Encoding]::UTF8.GetString((Get-EntryBytes $e)).ToLowerInvariant()
                foreach ($kw in (Get-Distinct $rxFp $jt)) { [void]$info.fp.Add($kw) }
            } catch {}
        }
        elseif ($low.EndsWith('.jar') -and $depth -lt $MAX_DEPTH -and ($RESERVED_WIN -notcontains $stem)) {
            try {
                if ($e.Length -le 64MB) {
                    $bytes = Get-EntryBytes $e
                    $ms = New-Object System.IO.MemoryStream(, $bytes)
                    $inner = New-Object System.IO.Compression.ZipArchive($ms, [System.IO.Compression.ZipArchiveMode]::Read)
                    [void]$info.nested.Add($prefix + $n)
                    Scan-Zip $inner $info ($depth + 1) "$prefix$n!/"
                    $inner.Dispose()
                }
            } catch { [void]$info.notes.Add("jar interno ilegible: $n") }
        }
    }
}

function Analyze-Jar($file, $wl, $bad, $banned) {
    $res = @{
        file = $file.FullName; name = $file.Name; sha256 = ''; sha512 = ''; size = $file.Length
        mtime = $file.LastWriteTime; score = 0
        reasons = (New-Object System.Collections.ArrayList); info = $null
    }
    $fs = $null; $zip = $null
    $bannedHit = $false
    try {
        $fs = New-Object System.IO.FileStream($file.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
              ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $res.sha256 = (($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) -join '')
        $fs.Position = 0
        $sha512 = [System.Security.Cryptography.SHA512]::Create()
        $res.sha512 = (($sha512.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) -join '')
        $fs.Position = 0

        if ($bad -contains $res.sha256) { $res.score += 10; [void]$res.reasons.Add('HASH en lista negra') }
        if ($KNOWN_HASHES.ContainsKey($res.sha256)) { $res.score += 10; $bannedHit = $true; [void]$res.reasons.Add("HASH conocido: $($KNOWN_HASHES[$res.sha256])") }

        $info = New-Info
        $res.info = $info
        try {
            $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Read)
            Scan-Zip $zip $info 0 ''
        } catch [System.IO.InvalidDataException] {
            $res.score += 6
            [void]$res.reasons.Add('No es un zip/jar valido (corrupto o falso)')
            return $res
        }
    } catch {
        [void]$res.reasons.Add("No se pudo leer el archivo: $($_.Exception.Message)")
        return $res
    } finally {
        if ($zip) { $zip.Dispose() }
        if ($fs)  { $fs.Dispose() }
    }

    # --- hashes / lista blanca
    if ($null -ne $wl -and -not ($wl -contains $res.sha256)) {
        $res.score += 3; [void]$res.reasons.Add('Hash NO esta en la lista blanca')
    }

    # --- firmas de clientes/hacks
    if ($info.strong.Count -gt 0) {
        $res.score += 10
        [void]$res.reasons.Add("Firmas de cliente/hack ($($info.strong.Count)): " + (($info.strong | Sort-Object | Select-Object -First 4) -join '; '))
    }
    $badIds = @()
    foreach ($i in $info.ids)   { if ($BAD_MOD_IDS -contains $i) { $badIds += $i } }
    foreach ($i in $info.names) { if ($BAD_MOD_IDS -contains $i) { $badIds += $i } }
    if ($badIds.Count -gt 0) {
        $res.score += 10
        [void]$res.reasons.Add('ID/nombre de mod conocido como cheat: ' + (($badIds | Select-Object -Unique) -join ', '))
    }
    if ($info.weak.Count -ge 3) {
        $res.score += 4
        [void]$res.reasons.Add('Varios modulos tipo hack: ' + (($info.weak | Sort-Object) -join ', '))
    }

    # --- mods prohibidos por reglas
    $fname = Norm-Id $res.name
    $idNorm = @{}
    foreach ($i in $info.ids)   { $idNorm[(Norm-Id $i)] = $true }
    foreach ($i in $info.names) { $idNorm[(Norm-Id $i)] = $true }
    foreach ($key in $banned.Keys) {
        $k = Norm-Id $key
        if ($idNorm.ContainsKey($k) -or $fname.Contains($k)) {
            $res.score += 10
            [void]$res.reasons.Add("MOD PROHIBIDO por reglas ('$key'): $($banned[$key])")
            $bannedHit = $true
            break
        }
    }

    # --- suplantacion
    foreach ($mid in $info.ids0) {
        if ($LEGIT_PKGS.ContainsKey($mid)) {
            $exp = $LEGIT_PKGS[$mid]
            $ok = $false
            foreach ($nm in $info.names_list) {
                foreach ($p in $exp) { if ($nm.StartsWith($p)) { $ok = $true; break } }
                if ($ok) { break }
            }
            if (-not $ok) {
                $pk = @($info.names_list | Where-Object { $_.EndsWith('.class') -and ($_.Split('/').Length -ge 3) } |
                        ForEach-Object { $s = $_.Split('/'); "$($s[0])/$($s[1])" } | Select-Object -Unique -First 3)
                $res.score += 10
                [void]$res.reasons.Add("SUPLANTACION: dice ser '$mid' pero su codigo no es de $($exp[0]) (paquetes reales: $($pk -join ', '))")
            }
        }
    }

    # --- huellas de comportamiento (detecta mods prohibidos renombrados / bypass)
    if (-not $bannedHit) {
        foreach ($fam in $FAMILIES) {
            $okAll = $true
            foreach ($grp in $fam.groups) {
                $hit = $false
                foreach ($tk in $grp) { if ($info.fp.Contains($tk)) { $hit = $true; break } }
                if (-not $hit) { $okAll = $false; break }
            }
            if ($okAll) {
                $res.score += 10
                [void]$res.reasons.Add("BYPASS/RENOMBRADO: tiene el comportamiento de '$($fam.name)' aunque el nombre/id sea otro - $($fam.why)")
            }
        }
    }

    if ($info.reserved.Count -gt 0) {
        $res.score += 6
        [void]$res.reasons.Add('Trucos anti-analisis: nombres reservados de Windows dentro del jar: ' + (($info.reserved | Sort-Object | Select-Object -First 5) -join ', '))
    }

    # --- totem
    if ($info.totem_names.Count -gt 0 -or $info.totem_content.Count -gt 0) {
        $items = $info.totem_content
        if ($info.totem_names.Count -gt 0) { $items = $info.totem_names; $res.score += 6 } else { $res.score += 4 }
        $total = $info.totem_names.Count + $info.totem_content.Count
        [void]$res.reasons.Add("Funciones de TOTEM tipo hack ($total): " + (($items | Sort-Object | Select-Object -First 3) -join '; '))
    }

    # --- evasion
    if ($info.evasion.Count -gt 0) {
        $res.score += 10
        [void]$res.reasons.Add("Herramienta de EVASION (self-destruct/anti-SS/limpiador) ($($info.evasion.Count)): " + (($info.evasion | Sort-Object | Select-Object -First 3) -join '; '))
    }
    if ($info.agent.Count -gt 0) {
        $res.score += 8
        [void]$res.reasons.Add('Java Agent en el manifest (' + (($info.agent | Sort-Object) -join ', ') + '): puede inyectarse en el juego y ocultarse')
    }
    if ($info.injection.Count -gt 0) {
        $res.score += 8
        [void]$res.reasons.Add('Patrones de INYECCION o manipulacion de procesos (' + (($info.injection | Sort-Object | Select-Object -First 6) -join ', ') + '): revisar DLL/agente y origen del mod')
    }
    $soft = New-Object System.Collections.ArrayList
    $procStrong = @($info.api_proc | Where-Object { $API_PROC_STRONG -contains $_ })
    $procWeak   = @($info.api_proc | Where-Object { $API_PROC_WEAK -contains $_ })
    if ($procStrong.Count -ge 1) {
        if ($procStrong.Count -ge 2) { $res.score += 4 } else { $res.score += 2 }
        [void]$res.reasons.Add('Ejecuta comandos/revisa procesos del sistema: ' + ((@($procStrong) + @($procWeak) | Sort-Object) -join ', ') + ' (posible deteccion de herramientas de analisis)')
    } elseif ($procWeak.Count -gt 0) {
        [void]$soft.Add('APIs de instrumentacion/procesos (normales en profilers): ' + (($procWeak | Sort-Object) -join ', '))
    }
    if ($info.api_gen.Count -ge 4) {
        [void]$soft.Add('Carga/descifra codigo (varias APIs juntas): ' + (($info.api_gen | Sort-Object) -join ', '))
    }
    $nx = @($info.natives | Where-Object { $_ -match '\.(exe|bat|cmd|ps1|vbs)$' })
    $nd = @($info.natives | Where-Object { $_ -match '\.dll$' })
    if ($nx.Count -gt 0) {
        $res.score += 4
        [void]$res.reasons.Add('Contiene ejecutables/scripts dentro del jar: ' + (($nx | Sort-Object | Select-Object -First 3) -join ', '))
    } elseif ($nd.Count -gt 0) {
        $res.score += 2
        [void]$res.reasons.Add('Contiene DLL dentro del jar: ' + (($nd | Sort-Object | Select-Object -First 3) -join ', '))
    }

    # --- ofuscacion
    $c = $info.classes
    $obf = @()
    if ($c -ge 10 -and ($info.short / $c) -gt 0.5) { $obf += "$($info.short)/$c clases con nombre de 1-2 letras" }
    if ($info.confusing -ge 5) { $obf += "$($info.confusing) clases tipo 'Il1I/OO0'" }
    if ($info.nonascii -ge 3)  { $obf += "$($info.nonascii) clases con caracteres unicode raros" }
    if ($c -ge 10 -and ($info.single_pkg / $c) -gt 0.5) { $obf += 'paquetes de 1-2 letras (a/b/c)' }
    if ($obf.Count -gt 0) {
        $res.score += 4
        [void]$res.reasons.Add('Posible ofuscacion: ' + ($obf -join ', '))
    }

    if (-not $info.metaFound) {
        $res.score += 2
        [void]$res.reasons.Add('Sin metadatos de mod (fabric.mod.json / mods.toml / mcmod.info)')
    }
    foreach ($note in $info.notes) { [void]$res.reasons.Add($note) }
    if ($res.score -gt 0) { foreach ($sn in $soft) { [void]$res.reasons.Add($sn) } }
    return $res
}

# ======================================================== COMPARACION OFICIAL MODRINTH
$MODRINTH_API = 'https://api.modrinth.com/v2'
$MODRINTH_UA = 'joshua1029XD/Ilegal-Mod-Fucker/1.8 (Minecraft screenshare scanner)'

function Resolve-Modrinth($results) {
    if ($NoModrinth) { return }
    $candidates = @($results | Where-Object { $_.sha512 -and $_.sha512.Length -eq 128 })
    if ($candidates.Count -eq 0) { return }

    Say '  Comparando SHA-512 con archivos publicados en Modrinth...' 'MEDIO'
    foreach ($r in $results) {
        $r.modrinth = [ordered]@{ status = 'NO VERIFICADO'; project_id = ''; version = ''; file = ''; detail = '' }
    }

    $payload = @{ hashes = @($candidates | ForEach-Object { $_.sha512 }); algorithm = 'sha512' } |
        ConvertTo-Json -Compress
    try {
        $response = Invoke-RestMethod -Uri "$MODRINTH_API/version_files" -Method Post `
            -Headers @{ 'User-Agent' = $MODRINTH_UA; 'Accept' = 'application/json' } `
            -ContentType 'application/json' -Body $payload -TimeoutSec 30 -ErrorAction Stop
    } catch {
        foreach ($r in $candidates) {
            $r.modrinth.status = 'NO VERIFICADO'
            $r.modrinth.detail = 'API de Modrinth no disponible: ' + $_.Exception.Message
        }
        Say '  Modrinth no respondio; se conserva el analisis local.' 'MEDIO'
        return
    }

    foreach ($r in $candidates) {
        $hit = $null
        $prop = $response.PSObject.Properties | Where-Object { $_.Name -eq $r.sha512 } | Select-Object -First 1
        if ($prop) { $hit = $prop.Value }
        if ($null -ne $hit) {
            $r.modrinth.status = 'HASH COINCIDE'
            $r.modrinth.project_id = [string]$hit.project_id
            $r.modrinth.version = [string]$hit.version_number
            $primary = @($hit.files | Where-Object { $_.primary } | Select-Object -First 1)
            if ($primary.Count -eq 0) { $primary = @($hit.files | Select-Object -First 1) }
            if ($primary.Count -gt 0) { $r.modrinth.file = [string]$primary[0].filename }
            $r.modrinth.detail = 'Archivo identico a una version publicada por Modrinth'
        } elseif ($r.info -and $r.info.modrinth_urls.Count -gt 0) {
            $r.modrinth.status = 'ENLACE DECLARADO / HASH NO COINCIDE'
            $r.modrinth.detail = 'El JAR contiene un enlace Modrinth, pero su SHA-512 no aparece como archivo oficial'
        } else {
            $r.modrinth.status = 'NO COINCIDE'
            $r.modrinth.detail = 'SHA-512 no encontrado entre los archivos publicados consultados'
        }
    }
}

# ======================================================== LOGS
function Scan-Logs([string]$root) {
    $found = New-Object System.Collections.ArrayList
    $logs = Join-Path $root 'logs'
    if (-not (Test-Path -LiteralPath $logs -PathType Container)) {
        [void]$found.Add('No existe la carpeta logs/ (borrada para ocultar rastros?)')
        return $found
    }
    $latest = Join-Path $logs 'latest.log'
    if ((Test-Path -LiteralPath $latest) -and ((Get-Item -LiteralPath $latest).Length -lt 300)) {
        [void]$found.Add('logs/latest.log casi vacio (limpiado a proposito?)')
    }
    $files = Get-ChildItem -LiteralPath $logs -File -Force | Sort-Object LastWriteTime -Descending | Select-Object -First 10
    foreach ($p in $files) {
        if ($p.Extension -ne '.gz' -and $p.Extension -ne '.log') { continue }
        try {
            $fs = [System.IO.File]::Open($p.FullName, 'Open', 'Read', 'ReadWrite')
            $src = $fs
            if ($p.Extension -eq '.gz') { $src = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Decompress) }
            $buf = New-Object byte[] (20MB)
            $read = 0
            while ($read -lt $buf.Length) {
                $n = $src.Read($buf, $read, $buf.Length - $read)
                if ($n -le 0) { break }
                $read += $n
            }
            $src.Dispose(); $fs.Dispose()
            $text = $latin1.GetString($buf, 0, $read).ToLowerInvariant()
            $hits = @{}
            foreach ($kw in (Get-Distinct $rxStrong  $text)) { $hits[$kw] = $true }
            foreach ($kw in (Get-Distinct $rxEvasion $text)) { $hits[$kw] = $true }
            $tm = $rxTotem.Match($text)
            if ($tm.Success) { $hits[$tm.Value] = $true }
            if ($hits.Count -gt 0) {
                [void]$found.Add("logs/$($p.Name): menciona " + (($hits.Keys | Sort-Object | Select-Object -First 6) -join ', '))
            }
        } catch {}
    }
    return $found
}

function Scan-Residues([string]$root) {
    $found = New-Object System.Collections.ArrayList
    $locations = @($root, (Join-Path $root 'config'), (Join-Path $root 'versions'),
                   (Join-Path $root 'logs'), (Join-Path $root 'crash-reports'))
    $seen = @{}
    foreach ($dir in $locations) {
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
        try { $items = @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue) } catch { continue }
        foreach ($item in $items) {
            $key = $item.FullName.ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $name = $item.Name.ToLowerInvariant()
            $native = $name -match '\.(dll|exe|bat|cmd|ps1|vbs|jar)$'
            if ($rxResidue.IsMatch($name) -or ($native -and $name -match '(inject|agent|ghost|client|loader|clean|bypass)')) {
                $seen[$key] = $true
                [void]$found.Add("Residuo sospechoso: $($item.FullName)")
            }
        }
    }
    return $found
}

# ======================================================== MAIN
$script:allCounts = @{ 'ALTO' = 0; 'MEDIO' = 0; 'BAJO' = 0; 'OK' = 0 }
$script:wlOut = [ordered]@{}

function Find-ModsDir([string]$p) {
    try { $item = Get-Item -LiteralPath $p -ErrorAction Stop } catch { return @($p, $null) }
    if (-not $item.PSIsContainer) { return @($p, $null) }
    if ($item.Name.ToLower() -eq 'mods') { return @($item.Parent.FullName, $item.FullName) }
    foreach ($c in @('mods', 'minecraft\mods', '.minecraft\mods')) {
        $cand = Join-Path $p $c
        if (Test-Path -LiteralPath $cand -PathType Container) {
            return @((Get-Item -LiteralPath $cand).Parent.FullName, $cand)
        }
    }
    return @($p, $null)
}

# Minecraft abierto ahora mismo: carpeta real del juego, -javaagent y mods extra por argumentos de la JVM
function Get-RunningMinecraft {
    $found = New-Object System.Collections.ArrayList
    try { $procs = Get-CimInstance Win32_Process -Filter "Name='javaw.exe' OR Name='java.exe'" -ErrorAction Stop }
    catch { return $found }
    foreach ($pr in $procs) {
        $cl = [string]$pr.CommandLine
        if (-not $cl) { continue }
        if ($cl -notmatch '(?i)minecraft|net\.fabricmc|cpw\.mods|neoforge|--gameDir') { continue }
        $dir = $null
        $m = [regex]::Match($cl, '--gameDir\s+(?:"([^"]+)"|(\S+))')
        if ($m.Success) { if ($m.Groups[1].Success) { $dir = $m.Groups[1].Value } else { $dir = $m.Groups[2].Value } }
        $agents = @()
        foreach ($am in [regex]::Matches($cl, '-javaagent:(?:"([^"]+)"|(\S+))')) {
            if ($am.Groups[1].Success) { $agents += $am.Groups[1].Value } else { $agents += $am.Groups[2].Value }
        }
        $lib = @()
        foreach ($lm in [regex]::Matches($cl, '-agentlib:\S+|-agentpath:\S+|-Xbootclasspath\S*')) { $lib += $lm.Value }
        $addMods = @()
        $fm = [regex]::Match($cl, '-Dfabric\.addMods=(?:"([^"]+)"|(\S+))')
        if ($fm.Success) {
            if ($fm.Groups[1].Success) { $v = $fm.Groups[1].Value } else { $v = $fm.Groups[2].Value }
            $addMods = @($v -split ';' | Where-Object { $_ })
        }
        [void]$found.Add(@{ ProcId = $pr.ProcessId; Dir = $dir; Agents = $agents; AgentLib = $lib; AddMods = $addMods })
    }
    return $found
}

# Instancias de launchers comunes
function Find-Instances {
    $cands = New-Object System.Collections.ArrayList
    $ad = $env:APPDATA
    $hm = $HOME
    if ($ad) {
        [void]$cands.Add((Join-Path $ad '.minecraft'))
        foreach ($sub in @('PrismLauncher\instances', 'PolyMC\instances', 'MultiMC\instances', 'ATLauncher\instances',
                           'gdlauncher_next\instances', 'ModrinthApp\profiles')) {
            $dir = Join-Path $ad $sub
            if (Test-Path -LiteralPath $dir -PathType Container) {
                foreach ($d in (Get-ChildItem -LiteralPath $dir -Directory -Force | Where-Object { $_.Name -notmatch '^\.|^_LAUNCHER' })) { [void]$cands.Add($d.FullName) }
            }
        }
    } else { [void]$cands.Add((Join-Path $hm '.minecraft')) }
    $cf = Join-Path $hm 'curseforge\minecraft\Instances'
    if (Test-Path -LiteralPath $cf -PathType Container) {
        foreach ($d in (Get-ChildItem -LiteralPath $cf -Directory -Force | Where-Object { $_.Name -notmatch '^\.|^_LAUNCHER' })) { [void]$cands.Add($d.FullName) }
    }
    return $cands
}

function Show-Results($list) {
    $sorted = $list | Sort-Object { $_.score } -Descending
    foreach ($r in $sorted) {
        $lv = Get-Level $r.score
        $script:allCounts[$lv]++
        $mrStatus = 'NO VERIFICADO'
        if ($r.modrinth) { $mrStatus = [string]$r.modrinth.status }
        elseif ($r.info -and $r.info.modrinth_urls.Count -gt 0) { $mrStatus = 'ENLACE EN METADATOS' }
        $displayLevel = $lv
        if ($mrStatus -ne 'HASH COINCIDE') { $displayLevel = 'MEDIO' }
        if ($lv -eq 'OK' -and -not $All) {
            Say ("[$displayLevel] $($r.name)  |  Modrinth: $mrStatus") $displayLevel
            continue
        }
        Say ''
        Say ("+-- [$displayLevel] $($r.name)  |  puntaje: $($r.score)") $displayLevel
        Say ("|   Archivo : $($r.file)")
        Say ("|   SHA-256 : $($r.sha256)")
        if ($r.sha512) { Say ("|   SHA-512 : $($r.sha512)") }
        Say ("|   Tamano  : {0:N0} KB  |  Modificado: {1:yyyy-MM-dd HH:mm}" -f ($r.size / 1KB), $r.mtime)
        if ($r.info -and $r.info.labels.Count -gt 0) { Say ("|   Mod     : " + (($r.info.labels | Select-Object -First 3) -join ', ')) }
        $mrLevel = 'MEDIO'
        if ($mrStatus -eq 'HASH COINCIDE') { $mrLevel = 'OK' }
        Say ("|   Modrinth: $mrStatus") $mrLevel
        if ($r.modrinth -and $r.modrinth.detail) { Say ("|   Detalle : $($r.modrinth.detail)") }
        if ($r.modrinth -and $r.modrinth.project_id) { Say ("|   Proyecto: $($r.modrinth.project_id)  |  Version: $($r.modrinth.version)") }
        if ($r.info -and $r.info.nested.Count -gt 0) { Say "|   Jars internos: $($r.info.nested.Count)" }
        if ($r.reasons.Count -gt 0) {
            Say '|   Motivos:'
            foreach ($reason in $r.reasons) { Say "|     - $reason" }
        }
        Say '+-----------------------------------------------------------------------'
    }
}

function Scan-Instance([string]$root, [string]$modsDir) {
    Say-Section 'ANALISIS DE INSTANCIA'
    Say "  Ruta de instancia: $root"
    if ($modsDir) { Say "  Carpeta de mods  : $modsDir" } else { Say '  Carpeta de mods  : no encontrada en esta instancia' 'MEDIO' }
    Say ''
    $results = New-Object System.Collections.ArrayList
    $extra = New-Object System.Collections.ArrayList

    foreach ($d in $CLIENT_DIRS) {
        $cand = Join-Path $root $d
        if (Test-Path -LiteralPath $cand) { [void]$extra.Add("Carpeta de cliente de hacks conocida: $cand") }
    }
    $vdir = Join-Path $root 'versions'
    if (Test-Path -LiteralPath $vdir -PathType Container) {
        foreach ($v in (Get-ChildItem -LiteralPath $vdir -Directory -Force)) {
            foreach ($w in $CLIENT_VERSION_WORDS) {
                if ($v.Name.ToLower().Contains($w)) { [void]$extra.Add("Version instalada sospechosa: $($v.Name)"); break }
            }
        }
    }
    foreach ($x in (Scan-Logs $root)) { [void]$extra.Add("[LOGS] $x") }
    foreach ($x in (Scan-Residues $root)) { [void]$extra.Add("[RESIDUO] $x") }

    if ($modsDir) {
        $files = @(Get-ChildItem -LiteralPath $modsDir -Recurse -File -Force | Sort-Object FullName)
        Say ("  Archivos encontrados: $($files.Count)")
        Say '  Escaneando contenido y huellas de comportamiento...'
        $script:lastProgressPct = -1
        $i = 0
        foreach ($f in $files) {
            $i++
            Show-ScanProgress $i $files.Count $f.Name
            $ext = $f.Extension.ToLower()
            $isZip = $false
            try {
                $s = [System.IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite')
                $buf = New-Object byte[] 4
                [void]$s.Read($buf, 0, 4)
                $s.Dispose()
                $isZip = ($buf[0] -eq 0x50 -and $buf[1] -eq 0x4B)
            } catch { [void]$extra.Add("No se pudo leer $($f.Name): $($_.Exception.Message)"); continue }

            if ($SUSPICIOUS_EXT -contains $ext) {
                $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $f.FullName).Hash.ToLower()
                $r = @{ name = $f.Name; file = $f.FullName; sha256 = $h; size = $f.Length; mtime = $f.LastWriteTime; score = 8
                        reasons = (New-Object System.Collections.ArrayList); info = $null }
                [void]$r.reasons.Add("Ejecutable/script ($ext) dentro de /mods")
                [void]$results.Add($r)
                continue
            }
            $isJarName = ($ext -eq '.jar') -or $f.Name.ToLower().EndsWith('.jar.disabled')
            if ($isJarName -or $isZip) {
                $r = Analyze-Jar $f $wl $bad $banned
                if (-not $isJarName) {
                    $r.score += 6
                    $label = $ext; if (-not $label) { $label = 'ninguna' }
                    [void]$r.reasons.Add("Jar disfrazado con extension '$label'")
                }
                if ($f.Name.ToLower().EndsWith('.jar.disabled')) { [void]$r.reasons.Add('Mod desactivado (.disabled)') }
                if ($RecentHours -gt 0 -and ((Get-Date) - $r.mtime).TotalHours -lt $RecentHours) {
                    $r.score += 1
                    [void]$r.reasons.Add(("Modificado hace {0:N1} h" -f ((Get-Date) - $r.mtime).TotalHours))
                }
                [void]$results.Add($r)
            }
        }
        Write-Host ("`r" + (' ' * 120) + "`r") -NoNewline
        Say '  Analisis de archivos completado.' 'OK'
    }

    foreach ($r in $results) { if ($null -ne $r.info) { $script:wlOut[$r.sha256] = $r.name } }
    Resolve-Modrinth $results
    Say-Section ("RESULTADOS  |  $($results.Count) archivo(s) analizado(s)")
    $modrinthCount = @($results | Where-Object { $_.modrinth -and $_.modrinth.status -eq 'HASH COINCIDE' }).Count
    $unknownPlatformCount = $results.Count - $modrinthCount
    Say ("  Modrinth: HASH COINCIDE $modrinthCount  |  Resto por revisar $unknownPlatformCount")
    Show-Results $results
    if ($extra.Count -gt 0) {
        Say-Section 'OTROS HALLAZGOS'
        foreach ($e in $extra) { Say "  * $e" }
        Say ''
    }
}

$BANNER_FONT = @{
  'M' = @('#...#','##.##','#.#.#','#...#','#...#')
  'O' = @('.###.','#...#','#...#','#...#','.###.')
  'D' = @('####.','#...#','#...#','#...#','####.')
  'F' = @('#####','#....','####.','#....','#....')
  'U' = @('#...#','#...#','#...#','#...#','.###.')
  'C' = @('.####','#....','#....','#....','.####')
  'K' = @('#...#','#..#.','###..','#..#.','#...#')
  'E' = @('#####','#....','###..','#....','#####')
  'R' = @('####.','#...#','####.','#..#.','#...#')
  'I' = @('#####','..#..','..#..','..#..','#####')
  'L' = @('#....','#....','#....','#....','#####')
  'G' = @('.####','#....','#..##','#...#','.###.')
  'A' = @('.###.','#...#','#####','#...#','#...#')
}
$BARRIER = @(
  '.....DDDD.....',
  '...DDRRRRDD...',
  '..DRRRRRRRRD..',
  '.DRRRRRDDRRRD.',
  '.DRRRRD..DRRD.',
  'DRRRRRRD..DRRD',
  'DRRRDRRRD.DRRD',
  'DRRD.DRRRDRRRD',
  'DRRD..DRRRRRRD',
  '.DRRD..DRRRRD.',
  '.DRRRDDRRRRRD.',
  '..DRRRRRRRRD..',
  '...DDRRRRDD...',
  '.....DDDD.....'
)

function Get-WordRows([string]$word, [string]$blk) {
    $rows = @('', '', '', '', '')
    foreach ($ch in $word.ToCharArray()) {
        $glyph = $BANNER_FONT[[string]$ch]
        for ($i = 0; $i -lt 5; $i++) { $rows[$i] += $glyph[$i].Replace('#', $blk).Replace('.', ' ') + ' ' }
    }
    return $rows
}

function Show-Banner {
    $edge = '+' + ('-' * 72) + '+'
    Write-Host ''
    Write-Host $edge -ForegroundColor DarkCyan
    Write-Host ("|  MINECRAFT MOD SCREENSHARE SCANNER  v$VERSION".PadRight(73) + '|') -ForegroundColor Cyan
    Write-Host '|  Analisis estatico  |  Solo lectura  |  Sin modificar archivos'.PadRight(74) -ForegroundColor Gray
    Write-Host $edge -ForegroundColor DarkCyan
    $blk = [string][char]0x2588
    try { if ([Console]::OutputEncoding.CodePage -ne 65001) { $blk = '#' } } catch { $blk = '#' }
    $mod = Get-WordRows 'ILEGAL' $blk
    $fck = Get-WordRows 'FUCKER' $blk
    for ($i = 0; $i -lt 5; $i++) {
        Write-Host ('  ' + $mod[$i] + '   ') -NoNewline -ForegroundColor Cyan
        Write-Host $fck[$i] -ForegroundColor Red
    }
    foreach ($row in $BARRIER) {
        Write-Host (' ' * 24) -NoNewline
        $k = 0
        while ($k -lt $row.Length) {
            $ch = $row[$k]
            $j = $k
            while ($j -lt $row.Length -and $row[$j] -eq $ch) { $j++ }
            $w = ' ' * (2 * ($j - $k))
            if ($ch -eq 'R') { Write-Host $w -NoNewline -BackgroundColor Red }
            elseif ($ch -eq 'D') { Write-Host $w -NoNewline -BackgroundColor DarkRed }
            else { Write-Host $w -NoNewline }
            $k = $j
        }
        Write-Host ''
    }
    Write-Host '  [OK] SOLO LECTURA   [SCAN] JAR + CLASS   [HASH] SHA-256   [SAFE] SIN SUBIDAS' -ForegroundColor DarkCyan
    Write-Host '  ------------------------------------------------------------------------' -ForegroundColor DarkGray
    Write-Host '                 firmas  |  ofuscacion  |  agentes  |  comportamiento' -ForegroundColor Gray
    Write-Host ''
    [void]$script:lines.Add("=== Minecraft Mod Screenshare Scanner v$VERSION ===")
}

# ---------------------------------------------------------------- seleccion de ruta e inicio
if (-not $Path) {
    $defaultScanPath = $null
    if ($env:APPDATA) { $defaultScanPath = Join-Path $env:APPDATA '.minecraft' }
    if (-not $defaultScanPath) { $defaultScanPath = Join-Path $HOME '.minecraft' }

    $edge = '+' + ('-' * 72) + '+'
    Write-Host $edge -ForegroundColor DarkCyan
    Write-Host '|  RUTA DE ESCANEO'.PadRight(74) -ForegroundColor Cyan
    Write-Host ("|  Predeterminada: $defaultScanPath").PadRight(74) -ForegroundColor Gray
    Write-Host $edge -ForegroundColor DarkCyan
    $scanInput = Read-Host '|  Escribe otra ruta o presiona ENTER'
    Write-Host $edge -ForegroundColor DarkCyan
    Write-Host ''
    if (-not [string]::IsNullOrWhiteSpace($scanInput)) {
        $Path = $scanInput.Trim().Trim('"')
    } else {
        $Path = $defaultScanPath
    }
}

# ---------------------------------------------------------------- arranque
try { $Host.UI.RawUI.WindowTitle = 'Ilegal Fucker - Screenshare Scanner' } catch {}
Show-Banner
Say "Fecha: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Say ''

# listas externas (opcionales)
$wl = $null
if ($Whitelist) {
    $j = Get-Content -Raw -LiteralPath $Whitelist | ConvertFrom-Json
    if ($j -is [System.Management.Automation.PSCustomObject]) { $wl = @($j.PSObject.Properties.Name) } else { $wl = @($j) }
}
$bad = @()
if ($BadHashes) {
    $bad = @(Get-Content -LiteralPath $BadHashes | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -and -not $_.StartsWith('#') })
}
$banned = @{}
foreach ($k in $BANNED_MODS.Keys) { $banned[$k] = $BANNED_MODS[$k] }
if ($BannedIds) {
    $bj = Get-Content -Raw -LiteralPath $BannedIds | ConvertFrom-Json
    foreach ($pp in $bj.PSObject.Properties) { $banned[$pp.Name] = [string]$pp.Value }
}

$targets = New-Object System.Collections.ArrayList
$seen = @{}
function Add-Target([string]$p, [bool]$force) {
    if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Container)) { return }
    $d = Find-ModsDir $p
    if (-not $d[1] -and -not $force) { return }
    $key = ("$($d[0])|$($d[1])").ToLower()
    if ($seen.ContainsKey($key)) { return }
    $seen[$key] = $true
    [void]$targets.Add(@{ root = $d[0]; mods = $d[1] })
}

$running = @(Get-RunningMinecraft)
$procFindings = New-Object System.Collections.ArrayList
$agentResults = New-Object System.Collections.ArrayList

if ($Path) {
    if (-not (Test-Path -LiteralPath $Path)) { Write-Host "No existe la ruta: $Path" -ForegroundColor Red; return }
    Add-Target $Path $true
} else {
    foreach ($g in $running) {
        if ($g.Dir) { Add-Target $g.Dir $true }
        foreach ($am in $g.AddMods) { Add-Target $am $true }
    }
    foreach ($inst in (Find-Instances)) { Add-Target $inst $false }
    if ($env:APPDATA) { Add-Target (Join-Path $env:APPDATA '.minecraft') $true }
}

# --- Minecraft en ejecucion
if ($running.Count -gt 0) {
    Say '--- Minecraft en ejecucion ---'
    foreach ($g in $running) {
        $gd = $g.Dir; if (-not $gd) { $gd = 'desconocido' }
        Say "  * PID $($g.ProcId) - gameDir: $gd"
        if ($g.AddMods.Count -gt 0) {
            Say "  * -Dfabric.addMods carga $($g.AddMods.Count) mod(s) extra (algunos launchers lo usan de forma legitima; se analiza el contenido)" 'MEDIO'
            foreach ($am in $g.AddMods) {
                if (Test-Path -LiteralPath $am -PathType Leaf) {
                    $mr = Analyze-Jar (Get-Item -LiteralPath $am) $wl $bad $banned
                    [void]$agentResults.Add($mr)
                }
            }
        }
        foreach ($lb in $g.AgentLib) { Say "  * ALERTA: argumento de JVM sospechoso: $lb" 'ALTO' }
        foreach ($a in $g.Agents) {
            Say "  * ALERTA: -javaagent cargado en el juego: $a" 'ALTO'
            $clean = ($a -split '=')[0]
            if (Test-Path -LiteralPath $clean -PathType Leaf) {
                $ar = Analyze-Jar (Get-Item -LiteralPath $clean) $wl $bad $banned
                $ar.score += 8
                [void]$ar.reasons.Add("Cargado como -javaagent en el proceso del juego (PID $($g.ProcId))")
                [void]$agentResults.Add($ar)
            }
        }
    }
    Say ''
    if ($agentResults.Count -gt 0) { Say '--- Mods/agentes cargados por argumentos de la JVM ---'; Show-Results $agentResults }
} else {
    Say 'No hay Minecraft abierto ahora mismo (se revisan solo los archivos de las instancias).'
    Say ''
}

if ($targets.Count -eq 0) {
    Say 'No encontre instancias de Minecraft automaticamente. Ejecuta de nuevo con -Path "C:\ruta\instancia" (o la carpeta mods).' 'MEDIO'
} else {
    foreach ($t in $targets) { Scan-Instance $t.root $t.mods }
}

if ($MakeWhitelist) {
    ($script:wlOut | ConvertTo-Json) | Set-Content -LiteralPath $MakeWhitelist -Encoding UTF8
    Say "[+] Lista blanca guardada con $($script:wlOut.Count) mods en $MakeWhitelist"
    Say ''
}

Say '--- Resumen ---'
Say "Instancias revisadas: $($targets.Count) | ALTO: $($script:allCounts['ALTO']) | MEDIO: $($script:allCounts['MEDIO']) | BAJO: $($script:allCounts['BAJO']) | OK: $($script:allCounts['OK'])"
Say 'Nota: no detecta clientes inyectados en memoria (DLL/ghost clients). Complementa con revision manual (procesos, recent files, logs, versiones).'

if ($Out) {
    $script:lines | Set-Content -LiteralPath $Out -Encoding UTF8
    Write-Host "`nReporte guardado en $Out"
}
