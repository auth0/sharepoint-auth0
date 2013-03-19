$modulespath = ($env:psmodulepath -split ";")[0]
$auth0path = "$modulespath\Auth0"

Write-Host "Creating module directory"
New-Item -Type Container -Force -path $pswatchpath | out-null

Write-Host "Downloading and installing"
(new-object net.webclient).DownloadString("https://raw.github.com/auth0/sharepoint-auth0/master/Auth0.psm1") | Out-File "$auth0\Auth0.psm1" 

Write-Host "Auth0 PowerShell Module Installed!"
Write-Host 'Use "Import-Module Auth0" and then Enable-Auth0'