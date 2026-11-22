# Renders the ZeroLeakage "negative-space shield" mark (rounded tile + shield with a slashed zero cut out).
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\New-AppIcon.ps1 -OutFile ZeroLeakage.UI\Assets\ZeroLeakage.ico
#   powershell -ExecutionPolicy Bypass -File tools\New-AppIcon.ps1 -PngFile ..\docs\assets\logo-512.png -PngSize 512
param([string]$OutFile, [string]$PngFile, [int]$PngSize = 512)

Add-Type -AssemblyName System.Drawing

$Tile = [System.Drawing.Color]::FromArgb(0x12, 0x15, 0x1E)
$Edge = [System.Drawing.Color]::FromArgb(0x26, 0x2C, 0x3D)
$Mint = [System.Drawing.Color]::FromArgb(0x00, 0xF5, 0xA0)

function P([double]$x, [double]$y, [double]$s, [double]$ox = 0, [double]$oy = 0) {
    New-Object System.Drawing.PointF ([float]($ox + $x * $s)), ([float]($oy + $y * $s))
}

# Draws the mark on a 96-unit grid at scale $s and offset ($ox,$oy). $cut is the colour of the cut-outs.
function Draw-Mark($g, [double]$s, [double]$ox, [double]$oy, $cut) {
    $shield = New-Object System.Drawing.Drawing2D.GraphicsPath
    $shield.AddLine((P 48 16 $s $ox $oy), (P 74 26 $s $ox $oy))
    $shield.AddLine((P 74 26 $s $ox $oy), (P 74 48 $s $ox $oy))
    $shield.AddBezier((P 74 48 $s $ox $oy), (P 74 64 $s $ox $oy), (P 62 74 $s $ox $oy), (P 48 80 $s $ox $oy))
    $shield.AddBezier((P 48 80 $s $ox $oy), (P 34 74 $s $ox $oy), (P 22 64 $s $ox $oy), (P 22 48 $s $ox $oy))
    $shield.AddLine((P 22 48 $s $ox $oy), (P 22 26 $s $ox $oy))
    $shield.CloseFigure()
    $g.FillPath((New-Object System.Drawing.SolidBrush $Mint), $shield)

    $pen = New-Object System.Drawing.Pen $cut, ([float](6 * $s))
    $g.DrawEllipse($pen, [float]($ox + 38 * $s), [float]($oy + 32 * $s), [float](20 * $s), [float](30 * $s))
    $slash = New-Object System.Drawing.Pen $cut, ([float](4 * $s))
    $slash.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $slash.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $g.DrawLine($slash, (P 40 58 $s $ox $oy), (P 56 36 $s $ox $oy))
}

function New-RoundRect([double]$x, [double]$y, [double]$w, [double]$h, [double]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = [float](2 * $r)
    $p.AddArc([float]$x, [float]$y, $d, $d, 180, 90)
    $p.AddArc([float]($x + $w - $d), [float]$y, $d, $d, 270, 90)
    $p.AddArc([float]($x + $w - $d), [float]($y + $h - $d), $d, $d, 0, 90)
    $p.AddArc([float]$x, [float]($y + $h - $d), $d, $d, 90, 90)
    $p.CloseFigure()
    return $p
}

function New-IconBitmap([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)
    $s = $size / 96.0
    $tilePath = New-RoundRect 0.5 0.5 ($size - 1) ($size - 1) (24 * $s)
    $g.FillPath((New-Object System.Drawing.SolidBrush $Tile), $tilePath)
    if ($size -ge 32) { $g.DrawPath((New-Object System.Drawing.Pen $Edge, ([float][Math]::Max(1, $s))), $tilePath) }
    # Small sizes: enlarge the shield inside the tile so it stays legible.
    if ($size -le 24) { $k = 1.25 } else { $k = 1.0 }
    $o = $size / 2 - 48 * $s * $k
    Draw-Mark $g ($s * $k) $o $o $Tile
    $g.Dispose()
    return $bmp
}

function Get-PngBytes($bmp) {
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    return ,$ms.ToArray()
}

if ($PngFile) {
    $dir = Split-Path -Parent $PngFile
    if ($dir) { New-Item -ItemType Directory -Force $dir | Out-Null }
    $b = New-IconBitmap $PngSize
    $b.Save($PngFile, [System.Drawing.Imaging.ImageFormat]::Png)
    $b.Dispose()
    Write-Host "Wrote $PngFile"
}

if ($OutFile) {
    $sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256
    $pngs = foreach ($sz in $sizes) { $b = New-IconBitmap $sz; ,(Get-PngBytes $b); $b.Dispose() }

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
}
