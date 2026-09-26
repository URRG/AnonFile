param(
    [string]$PythonPath = "",
    [int]$ApiPort = 8000,
    [int]$WebPort = 5173
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $PythonPath) {
    $PythonPath = Join-Path $repoRoot '.venv\Scripts\python.exe'
}
if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
    throw "Python environment not found at $PythonPath. See docs/synthetic-demo.md."
}
$vite = Join-Path $repoRoot 'apps\web\node_modules\vite\bin\vite.js'
if (-not (Test-Path -LiteralPath $vite -PathType Leaf)) {
    throw 'Web dependencies are missing. Run npm ci --ignore-scripts in apps/web first.'
}
$node = (Get-Command node -ErrorAction Stop).Source

# Generate a fresh local-only credential for this process tree. No token is
# committed or written to disk. Closing this launcher stops both services.
$random = New-Object byte[] 32
$generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $generator.GetBytes($random) } finally { $generator.Dispose() }
$token = [Convert]::ToBase64String($random).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$env:ANONFLOW_ENV = 'development'
$env:ANONFLOW_AUTH_MODE = 'dev-token'
$env:ANONFLOW_STORAGE_MODE = 'memory'
$env:ANONFLOW_DEMO_MODE = 'enabled'
$env:ANONFLOW_DEV_PRINCIPALS = ConvertTo-Json -Compress -InputObject @(
    @{ token = $token; subject = 'synthetic-demo-processor'; tenant = 'synthetic-demo'; roles = @('processor') }
)
$env:WEB_ORIGIN = "http://127.0.0.1:$WebPort,http://localhost:$WebPort"
$env:VITE_API_URL = "http://127.0.0.1:$ApiPort"

$runDir = Join-Path $repoRoot '.demo-run'
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$apiOut = Join-Path $runDir 'api.stdout.log'
$apiErr = Join-Path $runDir 'api.stderr.log'
$webOut = Join-Path $runDir 'web.stdout.log'
$webErr = Join-Path $runDir 'web.stderr.log'
$api = $null
$web = $null
try {
    $api = Start-Process -FilePath $PythonPath -ArgumentList @('-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', "$ApiPort") -WorkingDirectory (Join-Path $repoRoot 'services\api') -WindowStyle Hidden -PassThru -RedirectStandardOutput $apiOut -RedirectStandardError $apiErr
    $web = Start-Process -FilePath $node -ArgumentList @($vite, '--host', '127.0.0.1', '--port', "$WebPort", '--strictPort') -WorkingDirectory (Join-Path $repoRoot 'apps\web') -WindowStyle Hidden -PassThru -RedirectStandardOutput $webOut -RedirectStandardError $webErr

    $ready = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if ($api.HasExited -or $web.HasExited) { break }
        try {
            $health = Invoke-RestMethod -Uri "http://127.0.0.1:$ApiPort/health" -TimeoutSec 1
            $page = Invoke-WebRequest -Uri "http://127.0.0.1:$WebPort/" -TimeoutSec 1
            if ($health.mode -eq 'development' -and $page.StatusCode -eq 200) { $ready = $true; break }
        } catch { }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) {
        throw "Demo servers did not become ready. Check $apiErr and $webErr."
    }

    # Verify the opt-in route and generated credential before handing the demo
    # to a presenter. This request uses a fictional address and stores nothing.
    $smokeBody = @{ format = 'text'; content = 'Demo contact demo@example.test'; synthetic_only = $true } | ConvertTo-Json -Compress
    $smoke = Invoke-RestMethod -Uri "http://127.0.0.1:$ApiPort/demo/inspect" -Method Post -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body $smokeBody -TimeoutSec 5
    if ($smoke.posture -ne 'SYNTHETIC_DEMO_ONLY' -or $smoke.release_authorized -ne $false -or -not $smoke.transformed_preview.Contains('[REDACTED_EMAIL]')) {
        throw 'The synthetic demo inspection self-check failed.'
    }

    $demoFiles = @(
        @{ id = 'mail'; name = 'mail.txt'; content_base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("From: Riya <riya@example.test>`nTo: Sita <sita@example.test>")) },
        @{ id = 'record'; name = 'record.json'; content_base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"full_name":"Riya"}')) }
    )
    $batchBody = @{ files = $demoFiles; synthetic_only = $true } | ConvertTo-Json -Depth 5 -Compress
    $batch = Invoke-RestMethod -Uri "http://127.0.0.1:$ApiPort/demo/batch/inspect" -Method Post -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body $batchBody -TimeoutSec 5
    if ($batch.posture -ne 'SYNTHETIC_DEMO_ONLY' -or $batch.release_authorized -ne $false -or $batch.summary.files -ne 2 -or $batch.summary.explicit_relationships -ne 1) {
        throw 'The synthetic batch demo self-check failed.'
    }

    # Exercise the public fictional media fixtures before presenting a PDF/image
    # demo. The media bytes stay on loopback; this is not a redaction guarantee.
    $mediaRoot = Join-Path $repoRoot 'apps\web\public\demo-media'
    $mediaFiles = @(
        @{ id = 'pdf'; name = '01-email-thread.pdf'; content_base64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $mediaRoot '01-email-thread.pdf'))) },
        @{ id = 'image'; name = '02-service-note.png'; content_base64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $mediaRoot '02-service-note.png'))) },
        @{ id = 'record'; name = '03-support-record.json'; content_base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"client_name":"Sita","account_owner":"Riya","note":"Riya emailed Sita about DEMO-4822."}')) }
    )
    $mediaBody = @{ files = $mediaFiles; synthetic_only = $true } | ConvertTo-Json -Depth 5 -Compress
    $mediaCheck = Invoke-RestMethod -Uri "http://127.0.0.1:$ApiPort/demo/batch/inspect" -Method Post -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body $mediaBody -TimeoutSec 30
    if ($mediaCheck.posture -ne 'SYNTHETIC_DEMO_ONLY' -or $mediaCheck.export_available -ne $false -or
        $mediaCheck.summary.files -ne 3 -or $mediaCheck.summary.explicit_relationships -ne 2 -or
        $mediaCheck.documents[0].media_preview.pages.Count -ne 1 -or $mediaCheck.documents[1].media_preview.pages.Count -ne 1 -or
        $mediaCheck.documents[0].candidate_text.Contains('Riya') -or $mediaCheck.documents[1].candidate_text.Contains('Sita')) {
        throw 'The fictional PDF/image batch self-check failed.'
    }

    Write-Host "Synthetic demo: http://127.0.0.1:$WebPort/"
    Write-Host "Processor token (paste into the UI): $token"
    Write-Host 'Use only synthetic files. No production release or anonymity guarantee is available.'
    Read-Host 'Press Enter to stop both demo servers' | Out-Null
} finally {
    if ($web -and -not $web.HasExited) { Stop-Process -Id $web.Id -ErrorAction SilentlyContinue }
    if ($api -and -not $api.HasExited) { Stop-Process -Id $api.Id -ErrorAction SilentlyContinue }
}
