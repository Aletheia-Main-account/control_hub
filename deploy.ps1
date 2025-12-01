<#
.SYNOPSIS
    Hyper-Robust Deployment Script for Dynamic Control Hub
.DESCRIPTION
    1. Sanitizes Python scripts (CRLF -> LF) to prevent "Silent Disconnects".
    2. Packages source code, envs, and requirements.
    3. Prepares a 'dist' folder ready for SCP/Rsync to the production node.
#>

$SourceDir = Get-Location
$DistDir = Join-Path $SourceDir "dist"
$EnvFile = Join-Path $SourceDir "env\.env"

# --- 1. PREPARATION ---
Write-Host "[DEPLOY] Starting Deployment Sequence..." -ForegroundColor Cyan

if (Test-Path $DistDir) {
    Remove-Item $DistDir -Recurse -Force
    Write-Host "[CLEAN] Removed old dist/ folder." -ForegroundColor Gray
}
New-Item -ItemType Directory -Path $DistDir | Out-Null

# --- 2. FILE SELECTION (Manifest) ---
$FilesToDeploy = @(
    "control_hub.py",
    "streamlit_app.py",
    "app.py",
    "provenance_watcher.py",
    "create_mock_artifacts.py"
)

# --- 3. SANITIZATION ENGINE ---
foreach ($File in $FilesToDeploy) {
    $SourcePath = Join-Path $SourceDir $File
    $DestPath = Join-Path $DistDir $File

    if (Test-Path $SourcePath) {
        # Read file content
        $Content = Get-Content -Path $SourcePath -Raw
        
        # THE CRITICAL FIX: Force LF line endings
        # Windows uses \r\n. Linux hates \r. We remove \r.
        $Sanitized = $Content -replace "`r", ""
        
        # Write clean file to dist
        [System.IO.File]::WriteAllText($DestPath, $Sanitized)
        Write-Host "[OK] Processed & Sanitized: $File" -ForegroundColor Green
    } else {
        Write-Host "[ERROR] Missing critical file: $File" -ForegroundColor Red
        exit 1
    }
}

# --- 4. ENVIRONMENT & CONFIG ---
# FIX: Pointing to the 'env' folder for requirements
$ReqBase = Join-Path $SourceDir "env\requirements-base.txt"
$ReqUI = Join-Path $SourceDir "env\requirements-ui.txt"

if (Test-Path $ReqBase) {
    Copy-Item $ReqBase $DistDir
    Copy-Item $ReqUI $DistDir
    Write-Host "[OK] Requirements copied from env/ folder." -ForegroundColor Green
} else {
    Write-Host "[ERROR] Requirements files not found in env/ folder." -ForegroundColor Red
    exit 1
}

# Copy .env safely (Warn if missing)
if (Test-Path $EnvFile) {
    $EnvDest = Join-Path $DistDir ".env"
    Copy-Item $EnvFile $EnvDest
    Write-Host "[SECURE] Environment secrets copied." -ForegroundColor Yellow
} else {
    Write-Host "[WARN] No .env file found. Target will need manual config." -ForegroundColor Magenta
}

# --- 5. FINALIZE ---
Write-Host "`n[SUCCESS] Build Complete!" -ForegroundColor Cyan
Write-Host "Deployable artifacts are located in: $DistDir"
Write-Host "To run on target:"
Write-Host "  1. pip install -r requirements-base.txt"
Write-Host "  2. pip install -r requirements-ui.txt"
Write-Host "  3. python app.py  (In Term 1)"
Write-Host "  4. streamlit run streamlit_app.py (In Term 2)"