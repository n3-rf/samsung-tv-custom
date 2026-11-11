# prepare-usb.ps1 - Prepare le SanDisk pour l'exploit TV
# Doit etre lance en tant qu'administrateur
#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$disk = 1
$p1img = "C:\Users\theor\Documents\TV\exploit\out\umh-boot\p1.img"

Write-Host "=== Preparation USB SanDisk pour exploit TV ===" -ForegroundColor Cyan
Write-Host ""

# Verification
$d = Get-Disk -Number $disk
Write-Host "Disque $disk : $($d.FriendlyName) ($([math]::Round($d.Size/1GB,1)) GB)"
$parts = Get-Partition -DiskNumber $disk
Write-Host "Partitions actuelles:"
$parts | Format-Table PartitionNumber, @{L='Size_MB';E={[math]::Round($_.Size/1MB,1)}}, DriveLetter, Type -AutoSize

# Suppression partition 2 (32 Mo vide)
if ($parts.Count -ge 2) {
    $p2 = $parts | Where-Object { $_.PartitionNumber -eq 2 }
    if ($p2 -and $p2.Size -lt 100MB) {
        Write-Host "Suppression partition 2 ($([math]::Round($p2.Size/1MB,1)) Mo vide)..." -ForegroundColor Yellow
        Remove-Partition -DiskNumber $disk -PartitionNumber 2 -Confirm:$false
        Write-Host "OK" -ForegroundColor Green
    }
}

Start-Sleep -Seconds 2

# Creation partition 8 Mo pour le trigger exFAT
Write-Host "Creation partition 8 Mo pour le trigger..." -ForegroundColor Yellow
$newPart = New-Partition -DiskNumber $disk -Size 8388608 -GptType "{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}"
$partOffset = $newPart.Offset
$partNum = $newPart.PartitionNumber
Write-Host "Partition $partNum creee a offset $partOffset" -ForegroundColor Green

Start-Sleep -Seconds 2

# Ecriture p1.img raw sur la partition via le disque physique
Write-Host "Ecriture de p1.img ($([math]::Round((Get-Item $p1img).Length/1MB,1)) Mo) sur la partition..." -ForegroundColor Yellow
$data = [System.IO.File]::ReadAllBytes($p1img)
$fs = [System.IO.FileStream]::new("\\.\PhysicalDrive$disk", [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
$null = $fs.Seek($partOffset, [System.IO.SeekOrigin]::Begin)
$fs.Write($data, 0, $data.Length)
$fs.Flush()
$fs.Close()
Write-Host "OK - $($data.Length) octets ecrits" -ForegroundColor Green

# Verification : lire les premiers octets et verifier la signature exFAT
$fs2 = [System.IO.FileStream]::new("\\.\PhysicalDrive$disk", [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
$null = $fs2.Seek($partOffset, [System.IO.SeekOrigin]::Begin)
$check = New-Object byte[] 11
$null = $fs2.Read($check, 0, 11)
$fs2.Close()
$sig = [System.Text.Encoding]::ASCII.GetString($check, 3, 8).Trim()
if ($sig -eq "EXFAT") {
    Write-Host "Verification: signature exFAT OK" -ForegroundColor Green
} else {
    Write-Host "ATTENTION: signature '$sig' au lieu de 'EXFAT'" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== DONE ===" -ForegroundColor Cyan
Write-Host "La partition trigger est prete."
Write-Host "NE PAS formater cette partition si Windows le propose !"
Write-Host ""
Write-Host "Prochaine etape: lancer tools\listen.bat puis brancher la cle dans la TV"
Write-Host ""
Read-Host "Appuie sur Entree pour fermer"
