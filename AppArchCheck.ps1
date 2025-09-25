# 00-AppArchCheck.ps1
# Cross-platform detector for EXE, MSI, MSIX/APPX (incl. bundles)
# Works on Windows PowerShell 5.1 and PowerShell 7+ (Windows/macOS/Linux)

[CmdletBinding()]
param(
    [string]$Path = ".",
    [switch]$Recurse,
    [switch]$Quiet
)

# --- Environment & Assemblies ---
$IsWindowsCompat = ($PSVersionTable.PSEdition -eq 'Desktop') -or ($env:OS -eq 'Windows_NT')
try {
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
} catch { }

# Enable ANSI colors on PS7+ (macOS/Linux/Windows Terminal) if needed
if ($PSVersionTable.PSVersion.Major -ge 7) {
    if ($PSStyle.OutputRendering -eq 'PlainText') { $PSStyle.OutputRendering = 'ANSI' }
}

function Convert-BytesToMiB { param([long]$Bytes) [math]::Round($Bytes / 1MB, 2) }

function Map-ArchToken {
    param([string]$arch)
    if (-not $arch) { return 'Unknown' }
    switch -Regex ($arch.ToLower()) {
        '^(x86|intel|intel32|32)$'   { 'intel32' ; break }
        '^(x64|amd64|64)$'           { 'amd64'   ; break }
        '^(arm64)$'                  { 'arm64'   ; break }
        '^(arm)$'                    { 'arm'     ; break }
        '^(ia64|itanium)$'           { 'ia64'    ; break }
        '^(neutral|anycpu|any)$'     { 'neutral' ; break }
        default                      { 'Unknown' }
    }
}

# --- EXE ---
function Get-ExePlatform {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$File)
    if ($File -notmatch '(?i)\.exe$' -or -not (Test-Path -LiteralPath $File)) { return $null }

    $fs = $null; $br = $null
    try {
        $fs = [System.IO.File]::Open($File,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::Read)
        $br = New-Object System.IO.BinaryReader($fs)

        if ($br.ReadUInt16() -ne 0x5A4D) { return 'Unknown' } # MZ
        $fs.Seek(0x3C,[System.IO.SeekOrigin]::Begin) | Out-Null
        $peOffset = $br.ReadUInt32()
        $fs.Seek([int64]$peOffset,[System.IO.SeekOrigin]::Begin) | Out-Null
        if ($br.ReadUInt32() -ne 0x00004550) { return 'Unknown' } # PE\0\0

        switch ([int]$br.ReadUInt16()) {
            0x014C { 'intel32' }
            0x8664 { 'amd64'   }
            0xAA64 { 'arm64'   }
            0x01C4 { 'arm'     }
            0x0200 { 'ia64'    }
            default { 'Unknown' }
        }
    } catch { 'Error' }
    finally { if ($br){$br.Dispose()} ; if ($fs){$fs.Dispose()} }
}

# --- MSI ---
function Get-MsiPlatform {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$File)
    if ($File -notmatch '(?i)\.msi$' -or -not (Test-Path -LiteralPath $File)) { return $null }

    if ($IsWindowsCompat) {
        $installer = $null; $si = $null
        try {
            $installer = New-Object -ComObject WindowsInstaller.Installer
            $si = $installer.SummaryInformation($File,0)
            $template = $si.Property(7) # PID_TEMPLATE -> e.g. "Intel;1033", "x64;1033", "Arm64;1033"
            Map-ArchToken (($template -split ';')[0])
        } catch { 'Error' }
        finally {
            if ($si) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($si) }
            if ($installer) { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($installer) }
        }
    } else {
        'Unknown (MSI parsing requires Windows)'
    }
}

# --- MSIX / APPX (& bundles) ---
function Get-AppxMsixPlatform {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$File)

    if ($File -notmatch '(?i)\.(appx|msix|appxbundle|msixbundle)$' -or -not (Test-Path -LiteralPath $File)) { return $null }

    $zip = $null
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($File)

        # Try bundle manifest first (can live under AppxMetadata/...)
        $bundleEntry = $zip.Entries |
            Where-Object { $_.FullName -match '(?i)(^|/|\\)AppxBundleManifest\.xml$' } |
            Select-Object -First 1

        if ($bundleEntry) {
            $sr  = New-Object System.IO.StreamReader($bundleEntry.Open())
            $xml = [xml]$sr.ReadToEnd()
            $sr.Close(); $sr.Dispose()

            $pkgs = $xml.SelectNodes("/*[local-name()='AppxBundle']/*[local-name()='Packages']/*[local-name()='Package']")
            if (-not $pkgs -or $pkgs.Count -eq 0) { return 'Unknown' }

            $archs = @()
            foreach ($p in $pkgs) {
                $attr = $null
                if ($p.Attributes) {
                    $attr = $p.Attributes['ProcessorArchitecture']
                    if (-not $attr) { $attr = $p.Attributes['Architecture'] }
                }
                if ($attr) {
                    $tok = Map-ArchToken $attr.Value
                    if ($tok) { $archs += $tok }
                }
            }
            if ($archs.Count -gt 0) {
                ($archs | Where-Object { $_ } | Select-Object -Unique) -join ','
            } else {
                'Unknown'
            }
        }
        else {
            # Regular APPX/MSIX: find AppxManifest.xml anywhere
            $entry = $zip.Entries |
                Where-Object { $_.FullName -match '(?i)(^|/|\\)AppxManifest\.xml$' } |
                Select-Object -First 1
            if (-not $entry) { return 'Unknown' }

            $sr  = New-Object System.IO.StreamReader($entry.Open())
            $xml = [xml]$sr.ReadToEnd()
            $sr.Close(); $sr.Dispose()

            $idNode = $xml.SelectSingleNode("/*[local-name()='Package']/*[local-name()='Identity']")
            if (-not $idNode) { $idNode = $xml.SelectSingleNode("//*[local-name()='Identity']") }

            $arch = $null
            if ($idNode -and $idNode.Attributes) {
                $pa = $idNode.Attributes['ProcessorArchitecture']
                if ($pa) { $arch = $pa.Value }
            }
            if (-not $arch -or $arch -eq '') { $arch = 'neutral' }

            Map-ArchToken $arch
        }
    }
    catch { 'Error' }
    finally { if ($zip) { $zip.Dispose() } }
}

# --- Directory scan ---
function Get-PackagePlatformsInDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Recurse,
        [switch]$Quiet
    )

    if (-not (Test-Path -LiteralPath $Path)) { throw "Path not found: $Path" }

    $pattern = '(?i)\.(exe|msi|appx|msix|appxbundle|msixbundle)$'
    $files = Get-ChildItem -LiteralPath $Path -File -Recurse:$Recurse -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -match $pattern }

    if (-not $files) {
        if (-not $Quiet) { Write-Host "No supported packages found in '$Path'." -ForegroundColor Yellow }
        return
    }

    foreach ($f in $files) {
        $ext = [System.IO.Path]::GetExtension($f.Name).ToLowerInvariant()
        $plat = switch ($ext) {
            '.exe'         { Get-ExePlatform       -File $f.FullName ; break }
            '.msi'         { Get-MsiPlatform       -File $f.FullName ; break }
            '.appx'        { Get-AppxMsixPlatform  -File $f.FullName ; break }
            '.msix'        { Get-AppxMsixPlatform  -File $f.FullName ; break }
            '.appxbundle'  { Get-AppxMsixPlatform  -File $f.FullName ; break }
            '.msixbundle'  { Get-AppxMsixPlatform  -File $f.FullName ; break }
            default        { 'Unknown' }
        }

        if ($null -ne $plat) {
            # Return FileName directly so all consumers show the short name
            [pscustomobject]@{
                FileName = [System.IO.Path]::GetFileName($f.FullName)
                Size     = Convert-BytesToMiB $f.Length
                Platform = $plat
                FullPath = $f.FullName   # kept for reference if needed
            }
        }
    }
}

# --- Auto-run ---
if ($MyInvocation.MyCommand.Path -and $MyInvocation.InvocationName -ne '.') {
    $result = Get-PackagePlatformsInDirectory -Path $Path -Recurse:$Recurse -Quiet:$Quiet
    if ($result) {
        $rows = $result | Sort-Object FileName |
                Select-Object FileName, @{n='Size';e={ '{0:N2}' -f $_.Size }}, Platform

        # Calculate widths
        $fileNameWidth = [Math]::Max(8, ($rows | ForEach-Object { $_.FileName.Length } | Measure-Object -Maximum).Maximum)
        $sizeWidth     = [Math]::Max(4, ($rows | ForEach-Object { $_.Size.Length }     | Measure-Object -Maximum).Maximum)
        $platWidth     = [Math]::Max(8, ($rows | ForEach-Object { $_.Platform.Length } | Measure-Object -Maximum).Maximum)

        # Spacing above
        Write-Host ""

        if ($PSVersionTable.PSVersion.Major -ge 7) {
            # PS7+: ANSI colors (true orange)
            $reset  = $PSStyle.Reset
            $hdr    = $PSStyle.Foreground.Green
            $white  = $PSStyle.Foreground.White
            $orange = $PSStyle.Foreground.Rgb(255,165,0)
            $yellow = $PSStyle.Foreground.Yellow

            Write-Host ($hdr + ("{0,-$fileNameWidth} {1,$sizeWidth} {2,-$platWidth}" -f 'FileName','Size','Platform') + $reset)
            Write-Host ($hdr + ("{0,-$fileNameWidth} {1,$sizeWidth} {2,-$platWidth}" -f ('-'*8),('----'),('--------')) + $reset)

            foreach ($row in $rows) {
                $left = ("{0,-$fileNameWidth} " -f $row.FileName)
                $mid  = ("{0,$sizeWidth} "     -f $row.Size)
                $right= ("{0,-$platWidth}"     -f $row.Platform)

                Write-Host -NoNewline ($white  + $left  + $reset)
                Write-Host -NoNewline ($orange + $mid   + $reset)
                Write-Host              ($yellow + $right + $reset)
            }
        }
        else {
            # PS5.1: named colors (DarkYellow ~ orange-ish)
            Write-Host ("{0,-$fileNameWidth} {1,$sizeWidth} {2,-$platWidth}" -f 'FileName','Size','Platform') -ForegroundColor Green
            Write-Host ("{0,-$fileNameWidth} {1,$sizeWidth} {2,-$platWidth}" -f ('-'*8),('----'),('--------')) -ForegroundColor Green

            foreach ($row in $rows) {
                Write-Host ("{0,-$fileNameWidth} " -f $row.FileName) -ForegroundColor White -NoNewline
                Write-Host ("{0,$sizeWidth} "     -f $row.Size)     -ForegroundColor DarkYellow -NoNewline
                Write-Host ("{0,-$platWidth}"     -f $row.Platform) -ForegroundColor Yellow
            }
        }

        # Spacing below
        Write-Host ""
    }
}
