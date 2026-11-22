# Renders the WiX dialog artwork in the ZeroLeakage style.
#   Banner.bmp  493x58  - top strip on inner installer pages
#   Dialog.bmp  493x312 - left panel on the Welcome / Finish pages (text area is the right ~330px)
# Usage: powershell -ExecutionPolicy Bypass -File tools\New-InstallerArt.ps1 -OutDir ZeroLeakage.Installer\Art
param([Parameter(Mandatory)][string]$OutDir)

Add-Type -AssemblyName System.Drawing
New-Item -ItemType Directory -Force $OutDir | Out-Null

$Canvas = [System.Drawing.Color]::FromArgb(0x09, 0x0A, 0x0F)
$Tile   = [System.Drawing.Color]::FromArgb(0x12, 0x15, 0x1E)
$Mint   = [System.Drawing.Color]::FromArgb(0x00, 0xF5, 0xA0)
$Violet = [System.Drawing.Color]::FromArgb(0x7B, 0x61, 0xFF)
$Text   = [System.Drawing.Color]::FromArgb(0xED, 0xEF, 0xF5)
$Muted  = [System.Drawing.Color]::FromArgb(0x8A, 0x90, 0xA2)

function P([double]$x, [double]$y, [double]$s, [double]$ox, [double]$oy) {
    New-Object System.Drawing.PointF ([float]($ox + $x * $s)), ([float]($oy + $y * $s))
}

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

function New-Graphics($bmp) {
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    return $g
}

# Banner: WiX draws black title text on the left, so keep the left 2/3 light and put the mark on the right.
$banner = New-Object System.Drawing.Bitmap 493, 58
$g = New-Graphics $banner
$g.Clear([System.Drawing.Color]::White)
$grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush (New-Object System.Drawing.Rectangle 300, 0, 193, 58), ([System.Drawing.Color]::White), $Canvas, ([float]0)
$grad.WrapMode = [System.Drawing.Drawing2D.WrapMode]::TileFlipX
$g.FillRectangle($grad, 301, 0, 192, 58)
$g.FillRectangle((New-Object System.Drawing.SolidBrush $Canvas), 420, 0, 73, 58)
Draw-Mark $g 0.62 427 -1 $Canvas
$g.FillRectangle((New-Object System.Drawing.SolidBrush $Mint), 0, 56, 493, 2)
$g.Dispose()
$banner.Save((Join-Path $OutDir 'Banner.bmp'), [System.Drawing.Imaging.ImageFormat]::Bmp)
$banner.Dispose()

# Dialog: dark brand panel on the left 164px, white text area on the right.
$dialog = New-Object System.Drawing.Bitmap 493, 312
$g = New-Graphics $dialog
$g.Clear([System.Drawing.Color]::White)
$g.FillRectangle((New-Object System.Drawing.SolidBrush $Canvas), 0, 0, 164, 312)
$ringPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(70, $Violet)), 1.5
$g.DrawEllipse($ringPen, 22, 40, 120, 120)
$ringPen2 = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(40, $Mint)), 1.5
$g.DrawEllipse($ringPen2, 7, 25, 150, 150)
Draw-Mark $g 1.15 27 45 $Canvas
$f1 = New-Object System.Drawing.Font 'Segoe UI Semibold', 13
$f2 = New-Object System.Drawing.Font 'Segoe UI', 13
$f3 = New-Object System.Drawing.Font 'Consolas', 7
$sz = $g.MeasureString('Zero', $f1)
$x0 = 82 - ($sz.Width + $g.MeasureString('Leakage', $f2).Width - 8) / 2
$g.DrawString('Zero', $f1, (New-Object System.Drawing.SolidBrush $Text), [float]$x0, 196)
$g.DrawString('Leakage', $f2, (New-Object System.Drawing.SolidBrush $Muted), [float]($x0 + $sz.Width - 8), 196)
$sf = New-Object System.Drawing.StringFormat
$sf.Alignment = [System.Drawing.StringAlignment]::Center
$g.DrawString('ZERO BITS LEAKED', $f3, (New-Object System.Drawing.SolidBrush $Mint), (New-Object System.Drawing.RectangleF 0, 226, 164, 14), $sf)
$g.FillRectangle((New-Object System.Drawing.SolidBrush $Mint), 162, 0, 2, 312)
$g.Dispose()
$dialog.Save((Join-Path $OutDir 'Dialog.bmp'), [System.Drawing.Imaging.ImageFormat]::Bmp)
$dialog.Dispose()

Write-Host "Wrote $OutDir\Banner.bmp and $OutDir\Dialog.bmp"
