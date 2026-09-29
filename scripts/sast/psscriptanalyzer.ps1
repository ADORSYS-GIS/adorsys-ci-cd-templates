param(
    [Parameter(Mandatory = $true)][string]$ScanPath,
    [Parameter(Mandatory = $true)][string]$OutFile
)
$ErrorActionPreference = 'Stop'
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module PSScriptAnalyzer, ConvertToSARIF -Scope CurrentUser -Force
$records = Invoke-ScriptAnalyzer -Path $ScanPath -Recurse -ErrorAction SilentlyContinue
$records | ConvertTo-SARIF -FilePath $OutFile
