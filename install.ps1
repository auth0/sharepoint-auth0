$modulespath = ($env:psmodulepath -split ";")[0]
$auth0path = "$modulespath\Auth0"

Write-Host "Creating module directory"
New-Item -Type Container -Force -path $auth0path | out-null

Write-Host "Downloading and installing"
$webclient = new-object net.webclient
$webclient.DownloadString("https://raw.github.com/auth0/sharepoint-auth0/master/Auth0.psm1") | Out-File "$auth0path\Auth0.psm1"
$webclient.DownloadString("https://raw.github.com/auth0/sharepoint-claimsprovider/master/Auth0.ClaimsProvider/bin/Release/Auth0.ClaimsProvider.wsp") | Out-File "$auth0path\Auth0.ClaimsProvider.wsp"

if (Get-Module "Auth0") { Remove-Module "Auth0" }

Import-Module "$auth0path\Auth0.psm1"

Write-Host "Auth0 PowerShell Module Installed and imported!"