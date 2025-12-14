# dump-for-chatbots.ps1
# Simple codebase dump: collects .md, .cs, and .razor files into one text file.

# ========= CONFIG: add files and folders here =========
$Targets = @(
  # Files (exact paths)
  ".\README.md",
  ".\DesignDoc.md",
  ".\AGENTS.md",

  # Folders (searched recursively)
  ".\SlurpJob",
  ".\SlurpJob.Tests"
)
# ======================================================

$OutFile = ".\context_dump.txt"
$Extensions = @(".md", ".cs", ".razor")

# Ensure output file is recreated (not appended)
if (Test-Path -LiteralPath $OutFile) {
  Remove-Item -LiteralPath $OutFile
}

New-Item -ItemType File -Path $OutFile | Out-Null

$allFiles = foreach ($t in $Targets) {
  if (Test-Path -LiteralPath $t -PathType Leaf) {
    Get-Item -LiteralPath $t
  }
  elseif (Test-Path -LiteralPath $t -PathType Container) {
    Get-ChildItem -LiteralPath $t -Recurse -File
  }
}

$allFiles |
  Where-Object { $Extensions -contains $_.Extension.ToLowerInvariant() } |
  Sort-Object FullName |
  ForEach-Object {
    Add-Content -LiteralPath $OutFile -Value ("`n===== FILE: {0} =====`n" -f $_.FullName)
    Get-Content -LiteralPath $_.FullName -Raw | Add-Content -LiteralPath $OutFile
  }

Write-Host "Dump written to: $OutFile"
