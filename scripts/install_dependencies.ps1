# Check if winget is available
if (!(Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Host "winget is not installed. Please install App Installer from Microsoft Store"
    exit 1
}

# Install nmap using winget
Write-Host "Installing nmap..."
winget install nmap.nmap

# Add nmap to PATH
$nmapPath = "C:\Program Files (x86)\Nmap"
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")

if (!($currentPath -like "*$nmapPath*")) {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$nmapPath", "Machine")
    Write-Host "Added nmap to system PATH"
}

Write-Host "Installation complete. Please restart your terminal to apply PATH changes."
