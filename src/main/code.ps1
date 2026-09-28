$SourcePath = ".\" 
$OutputFileName = "all_code.txt"
$FileFilter = "*.*" 

$ScriptFile = $MyInvocation.MyCommand.Source
$OutputFileFullPath = Join-Path (Resolve-Path $SourcePath) $OutputFileName

# --- DEFINING IGNORE LISTS (No Regex Needed) ---

# 1. Exact filenames to ignore anywhere
$IgnoredFiles = @(
    "icon.png", "icon.jpg"
)

# 2. Exact folder names to ignore anywhere (e.g., "xevi" ignores \etc\xevi, \lib\xevi, etc.)
$IgnoredDirectories = @(
    "sounds", "lang"
)

# --- END IGNORE LISTS ---

if (Test-Path $OutputFileFullPath) {
    Remove-Item $OutputFileFullPath
}

# Collect files and apply filters
$Files = Get-ChildItem -Path $SourcePath -Recurse -Include $FileFilter -File | 
    Where-Object { 
        $IsIgnored = $false

        # Rule 1: Skip the output file and the script itself
        if ($_.FullName -eq $OutputFileFullPath -or $_.FullName -eq $ScriptFile) {
            $IsIgnored = $true
        }
        # Rule 2: Skip if the file's exact name is in our IgnoredFiles list
        elseif ($_.Name -in $IgnoredFiles) {
            $IsIgnored = $true
        }
        # Rule 3: Skip if any parent folder is in our IgnoredDirectories list
        else {
            # This breaks a path like "C:\lib\net\file.lua" into an array: "C:", "lib", "net"
            $PathParts = $_.DirectoryName -split '[\\/]'
            
            foreach ($Folder in $IgnoredDirectories) {
                if ($Folder -in $PathParts) {
                    $IsIgnored = $true
                    break # Stop checking folders, we already know it's ignored
                }
            }
        }

        # Keep the file ONLY if it is NOT ignored
        -not $IsIgnored
    }

Write-Host "Found $($Files.Count) files. Processing..." -ForegroundColor Cyan

foreach ($File in $Files) {
    try {
        $Content = Get-Content -Path $File.FullName -Raw -ErrorAction Stop

        $Header = "File: $($File.FullName)"
        $BlockStart = "'''" 
        $BlockEnd = "'''"
        $Separator = "`r`n"
        $FinalText = $Header + $Separator + $BlockStart + $Separator + $Content + $Separator + $BlockEnd + $Separator + $Separator
        
        Add-Content -Path $OutputFileFullPath -Value $FinalText -Encoding UTF8
    }
    catch {
        Write-Warning "Failed to read file: $($File.FullName)"
    }
}

Write-Host "Output completely saved to: $OutputFileFullPath" -ForegroundColor Green