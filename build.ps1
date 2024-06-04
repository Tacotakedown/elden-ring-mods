$BINARIES = @(
    "adjust_fov",
    "disable_rune_loss",
    "skip_intro"
)

Write-Host "Available binaries:"
for ($i = 0; $i -lt $BINARIES.Count; $i++) {
    Write-Host "[$i] $($BINARIES[$i])"
}

$selectedIndices = Read-Host "Enter the indices of the binaries you want to build (comma-separated, e.g., '0,2')"

$indices = $selectedIndices.Split(',')

foreach ($index in $indices) {
    if ($index -match '^\d+$' -and $index -ge 0 -and $index -lt $BINARIES.Count) {
        Set-Location -Path $BINARIES[$index]
        cargo build
        Set-Location -Path ..
    }
    else {
        Write-Host "Invalid index: $index"
    }
}