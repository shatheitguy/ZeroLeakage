# Renders the ZeroLeakage hexagon + zero-drop mark into a multi-size .ico (PNG-compressed entries).
# Usage: powershell -ExecutionPolicy Bypass -File tools\New-AppIcon.ps1 -OutFile ZeroLeakage.UI\Assets\ZeroLeakage.ico
param([Parameter(Mandatory)][string]$OutFile)

Add-Type -AssemblyName System.Drawing

function New-IconPng([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)
    $s = $size / 32.0
    $mint = [System.Drawing.Color]::FromArgb(0x00, 0xF5, 0xA0)

    $hex = New-Object 'System.Drawing.PointF[]' 6
    for ($i = 0; $i -lt 6; $i++) {
        $a = [Math]::PI / 180 * (60 * $i - 90)
        $hex[$i] = New-Object System.Drawing.PointF ([float](16 * $s + 14.5 * $s * [Math]::Cos($a))), ([float](16 * $s + 14.5 * $s * [Math]::Sin($a)))
    }
    $g.FillPolygon((New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(0x09, 0x0A, 0x0F))), $hex)
    $pen = New-Object System.Drawing.Pen $mint, ([float](2.4 * $s))
    $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $g.DrawPolygon($pen, $hex)

    $drop = New-Object System.Drawing.SolidBrush $mint
    $g.FillEllipse($drop, [float](11.5 * $s), [float](13 * $s), [float](9 * $s), [float](9 * $s))
    $tri = @(
        (New-Object System.Drawing.PointF ([float](16 * $s)), ([float](7.5 * $s))),
        (New-Object System.Drawing.PointF ([float](20.2 * $s)), ([float](15 * $s))),
        (New-Object System.Drawing.PointF ([float](11.8 * $s)), ([float](15 * $s)))
    )
    $g.FillPolygon($drop, [System.Drawing.PointF[]]$tri)
    $g.Dispose()

    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return ,$ms.ToArray()
}

$sizes = 16, 24, 32, 48, 64, 128, 256
$pngs = foreach ($sz in $sizes) { ,(New-IconPng $sz) }

$dir = Split-Path -Parent $OutFile
if ($dir) { New-Item -ItemType Directory -Force $dir | Out-Null }
$fs = [System.IO.File]::Create($OutFile)
$w = New-Object System.IO.BinaryWriter $fs
$w.Write([UInt16]0); $w.Write([UInt16]1); $w.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $sz = $sizes[$i]; $len = $pngs[$i].Length
    $dim = if ($sz -ge 256) { 0 } else { $sz }
    $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([UInt16]1); $w.Write([UInt16]32); $w.Write([UInt32]$len); $w.Write([UInt32]$offset)
    $offset += $len
}
foreach ($p in $pngs) { $w.Write($p) }
$w.Close()
Write-Host "Wrote $OutFile"
