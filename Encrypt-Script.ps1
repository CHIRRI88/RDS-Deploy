#=============================================================================
# CHIRRI Script Encryption Tool
# 
# Encrypts PowerShell scripts using AES-256 with password-based key derivation
# Encrypted scripts prompt for password at runtime before executing
#
# Keep this tool and your plain-text scripts LOCAL - never upload to GitHub
#=============================================================================

$ErrorActionPreference = "Stop"
$scriptVersion = "1.0"

#-----------------------------------------------------------------------------
# ENCRYPTION FUNCTIONS
#-----------------------------------------------------------------------------

function ConvertTo-EncryptedScript {
    param(
        [Parameter(Mandatory)][string]$PlainText,
        [Parameter(Mandatory)][SecureString]$Password
    )
    
    # Convert SecureString to plain text for key derivation
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    
    # Generate random salt and IV
    $salt = New-Object byte[] 32
    $iv = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $rng.GetBytes($salt)
    $rng.GetBytes($iv)
    $rng.Dispose()
    
    # Derive key using PBKDF2
    $keyDerivation = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $passwordPlain, 
        $salt, 
        100000,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    $key = $keyDerivation.GetBytes(32)
    $keyDerivation.Dispose()
    
    # Clear password from memory
    $passwordPlain = $null
    [System.GC]::Collect()
    
    # Encrypt using AES-256-CBC
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    
    $encryptor = $aes.CreateEncryptor()
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
    
    $aes.Dispose()
    
    # Combine salt + iv + encrypted data
    $combined = New-Object byte[] ($salt.Length + $iv.Length + $encryptedBytes.Length)
    [Array]::Copy($salt, 0, $combined, 0, $salt.Length)
    [Array]::Copy($iv, 0, $combined, $salt.Length, $iv.Length)
    [Array]::Copy($encryptedBytes, 0, $combined, $salt.Length + $iv.Length, $encryptedBytes.Length)
    
    return [Convert]::ToBase64String($combined)
}

function ConvertFrom-EncryptedScript {
    param(
        [Parameter(Mandatory)][string]$EncryptedBase64,
        [Parameter(Mandatory)][SecureString]$Password
    )
    
    # Convert SecureString to plain text for key derivation
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    
    # Decode base64
    $combined = [Convert]::FromBase64String($EncryptedBase64)
    
    # Extract salt, iv, and encrypted data
    $salt = New-Object byte[] 32
    $iv = New-Object byte[] 16
    $encryptedBytes = New-Object byte[] ($combined.Length - 48)
    
    [Array]::Copy($combined, 0, $salt, 0, 32)
    [Array]::Copy($combined, 32, $iv, 0, 16)
    [Array]::Copy($combined, 48, $encryptedBytes, 0, $encryptedBytes.Length)
    
    # Derive key using PBKDF2
    $keyDerivation = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $passwordPlain, 
        $salt, 
        100000,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    $key = $keyDerivation.GetBytes(32)
    $keyDerivation.Dispose()
    
    # Clear password from memory
    $passwordPlain = $null
    [System.GC]::Collect()
    
    # Decrypt using AES-256-CBC
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    
    $decryptor = $aes.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
    
    $aes.Dispose()
    
    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
}

function New-EncryptedScriptFile {
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][SecureString]$Password
    )
    
    # Read source script
    $sourceContent = Get-Content -Path $SourcePath -Raw
    
    # Encrypt the content
    $encryptedBlob = ConvertTo-EncryptedScript -PlainText $sourceContent -Password $Password
    
    # Build the wrapper script using single quotes to avoid parsing issues
    $wrapperScript = '#=============================================================================
# CHIRRI RDS Deployment - Encrypted Script
# This script requires a password to execute
#=============================================================================

$ErrorActionPreference = "Stop"

function ConvertFrom-EncryptedPayload {
    param(
        [Parameter(Mandatory)][string]$EncryptedBase64,
        [Parameter(Mandatory)][SecureString]$Password
    )
    
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    
    $combined = [Convert]::FromBase64String($EncryptedBase64)
    
    $salt = New-Object byte[] 32
    $iv = New-Object byte[] 16
    $encryptedBytes = New-Object byte[] ($combined.Length - 48)
    
    [Array]::Copy($combined, 0, $salt, 0, 32)
    [Array]::Copy($combined, 32, $iv, 0, 16)
    [Array]::Copy($combined, 48, $encryptedBytes, 0, $encryptedBytes.Length)
    
    $keyDerivation = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $passwordPlain, 
        $salt, 
        100000,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    $key = $keyDerivation.GetBytes(32)
    $keyDerivation.Dispose()
    
    $passwordPlain = $null
    [System.GC]::Collect()
    
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    
    $decryptor = $aes.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
    
    $aes.Dispose()
    
    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
}

# Encrypted payload
$encryptedPayload = "###ENCRYPTED_BLOB###"

# Prompt for password
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " CHIRRI BV Remote Desktop Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
$securePassword = Read-Host "Enter setup password" -AsSecureString

# Attempt decryption and execution
try {
    $decryptedScript = ConvertFrom-EncryptedPayload -EncryptedBase64 $encryptedPayload -Password $securePassword
    Invoke-Expression $decryptedScript
}
catch {
    Write-Host ""
    Write-Host "ERROR: Invalid password or corrupted data." -ForegroundColor Red
    Write-Host ""
    Write-Host "If you believe this is an error, contact IT support." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}
'

    # Insert the encrypted blob
    $wrapperScript = $wrapperScript -replace '###ENCRYPTED_BLOB###', $encryptedBlob
    
    # Write the output file
    [System.IO.File]::WriteAllText($OutputPath, $wrapperScript, [System.Text.UTF8Encoding]::new($false))
}

#-----------------------------------------------------------------------------
# MENU FUNCTIONS
#-----------------------------------------------------------------------------

function Show-Menu {
    Clear-Host
    Write-Host ""
    Write-Host "  =======================================================" -ForegroundColor Cyan
    Write-Host "  |                                                     |" -ForegroundColor Cyan
    Write-Host "  |        CHIRRI Script Encryption Tool v$scriptVersion           |" -ForegroundColor Cyan
    Write-Host "  |                                                     |" -ForegroundColor Cyan
    Write-Host "  =======================================================" -ForegroundColor Cyan
    Write-Host "  |                                                     |" -ForegroundColor Cyan
    Write-Host "  |   [1] Encrypt Install-BV-Remote.ps1                 |" -ForegroundColor White
    Write-Host "  |   [2] Encrypt Uninstall-BV-Remote.ps1               |" -ForegroundColor White
    Write-Host "  |   [3] Encrypt Both                                  |" -ForegroundColor White
    Write-Host "  |   [4] Decrypt a Script                              |" -ForegroundColor White
    Write-Host "  |   [5] Exit                                          |" -ForegroundColor White
    Write-Host "  |                                                     |" -ForegroundColor Cyan
    Write-Host "  =======================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Get-EncryptionPassword {
    param([string]$Action = "encryption")
    
    Write-Host ""
    $password1 = Read-Host "Enter $Action password" -AsSecureString
    $password2 = Read-Host "Confirm password" -AsSecureString
    
    # Compare passwords
    $BSTR1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password1)
    $BSTR2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password2)
    $plain1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR1)
    $plain2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR2)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR1)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR2)
    
    if ($plain1 -ne $plain2) {
        $plain1 = $null
        $plain2 = $null
        [System.GC]::Collect()
        Write-Host ""
        Write-Host "ERROR: Passwords do not match!" -ForegroundColor Red
        return $null
    }
    
    if ($plain1.Length -lt 8) {
        $plain1 = $null
        $plain2 = $null
        [System.GC]::Collect()
        Write-Host ""
        Write-Host "ERROR: Password must be at least 8 characters!" -ForegroundColor Red
        return $null
    }
    
    $plain1 = $null
    $plain2 = $null
    [System.GC]::Collect()
    
    return $password1
}

function Invoke-EncryptScript {
    param(
        [Parameter(Mandatory)][string]$SourceFile,
        [Parameter(Mandatory)][string]$OutputFile,
        [Parameter(Mandatory)][SecureString]$Password,
        [Parameter(Mandatory)][string]$ScriptDirectory
    )
    
    $sourcePath = Join-Path $ScriptDirectory $SourceFile
    $outputPath = Join-Path $ScriptDirectory $OutputFile
    
    # Check source exists
    if (!(Test-Path $sourcePath)) {
        Write-Host ""
        Write-Host "ERROR: Source file not found: $sourcePath" -ForegroundColor Red
        return $false
    }
    
    # Encrypt
    try {
        New-EncryptedScriptFile -SourcePath $sourcePath -OutputPath $outputPath -Password $Password
        Write-Host ""
        Write-Host "  OK " -ForegroundColor Green -NoNewline
        Write-Host "Created: $OutputFile" -ForegroundColor White
        return $true
    }
    catch {
        Write-Host ""
        Write-Host "ERROR: Failed to encrypt $SourceFile" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        return $false
    }
}

function Invoke-DecryptScript {
    param(
        [Parameter(Mandatory)][string]$ScriptDirectory
    )
    
    # Find encrypted scripts in current folder
    $encryptedFiles = Get-ChildItem -Path $ScriptDirectory -Filter "*-Encrypted.ps1" -File
    
    Write-Host ""
    
    if ($encryptedFiles.Count -eq 0) {
        Write-Host "No encrypted scripts found in current folder." -ForegroundColor Yellow
        Write-Host "Looking for files matching '*-Encrypted.ps1'" -ForegroundColor Gray
        return
    }
    
    Write-Host "Encrypted scripts found:" -ForegroundColor Yellow
    Write-Host ""
    
    $i = 1
    foreach ($file in $encryptedFiles) {
        Write-Host "  [$i] $($file.Name)" -ForegroundColor White
        $i++
    }
    
    Write-Host ""
    
    $selection = Read-Host "Select script to decrypt"
    
    # Handle selection
    if ([string]::IsNullOrWhiteSpace($selection)) {
        Write-Host ""
        Write-Host "No selection made." -ForegroundColor Yellow
        return
    }
    
    $inputPath = $null
    
    if ($selection -match '^\d+$') {
        $index = [int]$selection - 1
        if ($index -ge 0 -and $index -lt $encryptedFiles.Count) {
            $inputPath = $encryptedFiles[$index].FullName
        }
        else {
            Write-Host ""
            Write-Host "Invalid selection." -ForegroundColor Red
            return
        }
    }
    else {
        Write-Host ""
        Write-Host "Invalid selection." -ForegroundColor Red
        return
    }
    
    # Get password
    Write-Host ""
    $password = Read-Host "Enter decryption password" -AsSecureString
    
    # Read the encrypted file and extract the payload
    try {
        $fileContent = Get-Content -Path $inputPath -Raw
        
        # Extract the encrypted blob - look for the variable assignment
        $pattern = '\$encryptedPayload\s*=\s*"([^"]+)"'
        if ($fileContent -match $pattern) {
            $encryptedBlob = $matches[1].Trim()
        }
        else {
            Write-Host ""
            Write-Host "ERROR: Could not find encrypted payload in file." -ForegroundColor Red
            Write-Host "Make sure this is an encrypted script file." -ForegroundColor Yellow
            return
        }
        
        # Decrypt
        $decrypted = ConvertFrom-EncryptedScript -EncryptedBase64 $encryptedBlob -Password $password
        
        Write-Host ""
        Write-Host "Decryption successful!" -ForegroundColor Green
        
        # Create Decrypted subfolder if needed
        $decryptedFolder = Join-Path $ScriptDirectory "Decrypted"
        if (!(Test-Path $decryptedFolder)) {
            New-Item -ItemType Directory -Path $decryptedFolder -Force | Out-Null
            Write-Host ""
            Write-Host "  Created folder: Decrypted\" -ForegroundColor Gray
        }
        
        # Build output filename
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($inputPath) -replace '-Encrypted', ''
        $outputName = "$baseName-Decrypted.ps1"
        $outputPath = Join-Path $decryptedFolder $outputName
        
        # Save file
        $decrypted | Out-File -FilePath $outputPath -Encoding UTF8 -Force
        
        Write-Host ""
        Write-Host "  OK " -ForegroundColor Green -NoNewline
        Write-Host "Saved: Decrypted\$outputName" -ForegroundColor White
    }
    catch {
        Write-Host ""
        Write-Host "ERROR: Decryption failed. Invalid password or corrupted file." -ForegroundColor Red
    }
}



#-----------------------------------------------------------------------------
# MAIN LOOP
#-----------------------------------------------------------------------------

# Get script directory reliably
if ($PSScriptRoot) {
    $scriptDir = $PSScriptRoot
}
else {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
    if ([string]::IsNullOrEmpty($scriptDir)) {
        $scriptDir = Get-Location
    }
}

Set-Location $scriptDir

Write-Host ""
Write-Host "  Working directory: $scriptDir" -ForegroundColor Gray
Start-Sleep -Milliseconds 500

do {
    Show-Menu
    $selection = Read-Host "  Select option"
    
    switch ($selection) {
        "1" {
            $password = Get-EncryptionPassword
            if ($password) {
                Invoke-EncryptScript -SourceFile "Install-BV-Remote.ps1" `
                                     -OutputFile "Install-BV-Remote-Encrypted.ps1" `
                                     -Password $password `
                                     -ScriptDirectory $scriptDir
                Write-Host ""
                Write-Host "  Upload 'Install-BV-Remote-Encrypted.ps1' to GitHub." -ForegroundColor Yellow
            }
            Write-Host ""
            Read-Host "  Press Enter to continue"
        }
        "2" {
            $password = Get-EncryptionPassword
            if ($password) {
                Invoke-EncryptScript -SourceFile "Uninstall-BV-Remote.ps1" `
                                     -OutputFile "Uninstall-BV-Remote-Encrypted.ps1" `
                                     -Password $password `
                                     -ScriptDirectory $scriptDir
                Write-Host ""
                Write-Host "  Upload 'Uninstall-BV-Remote-Encrypted.ps1' to GitHub." -ForegroundColor Yellow
            }
            Write-Host ""
            Read-Host "  Press Enter to continue"
        }
        "3" {
            $password = Get-EncryptionPassword
            if ($password) {
                $success1 = Invoke-EncryptScript -SourceFile "Install-BV-Remote.ps1" `
                                                  -OutputFile "Install-BV-Remote-Encrypted.ps1" `
                                                  -Password $password `
                                                  -ScriptDirectory $scriptDir
                $success2 = Invoke-EncryptScript -SourceFile "Uninstall-BV-Remote.ps1" `
                                                  -OutputFile "Uninstall-BV-Remote-Encrypted.ps1" `
                                                  -Password $password `
                                                  -ScriptDirectory $scriptDir
                
                if ($success1 -or $success2) {
                    Write-Host ""
                    Write-Host "  -------------------------------------------------------" -ForegroundColor Gray
                    Write-Host ""
                    Write-Host "  Upload encrypted files to GitHub." -ForegroundColor Yellow
                }
            }
            Write-Host ""
            Read-Host "  Press Enter to continue"
        }
        "4" {
            Invoke-DecryptScript -ScriptDirectory $scriptDir
            Write-Host ""
            Read-Host "  Press Enter to continue"
        }
        "5" {
            Write-Host ""
            Write-Host "  Goodbye!" -ForegroundColor Cyan
            Write-Host ""
            exit
        }
        default {
            Write-Host ""
            Write-Host "  Invalid selection. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($true)
