param([string]$name = 'fig_arch', [int]$dpi = 220)
$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot
& tectonic "$name.tex" 2>&1 | Where-Object { $_ -match 'error|Error|Overfull|Undefined|!' } | Select-Object -First 10
& python -c "import fitz,sys; d=fitz.open('$name.pdf'); p=d[0].get_pixmap(dpi=$dpi); p.save('$name.png'); print('png', p.width, p.height)"
