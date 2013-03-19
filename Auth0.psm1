function GetFederationMetadata { param ([string]$url)
  $webclient = New-Object System.Net.WebClient
  
  Write-Verbose "Downloading federation metadata from $url"
  
  $data = $webclient.DownloadData($url);
  $ms = new-object io.memorystream(,$data);
  $ms.Flush();
  $ms.Position = 0;
  $fedMetadata = new-object XML
  $fedMetadata.Load($ms)
  
  return $fedMetadata
}

function GetCertificate { param ([xml]$fedMetadata)

  $ns = @{xsi = 'http://www.w3.org/2001/XMLSchema-instance'}
  $roleDescriptor = Select-Xml "//*[@xsi:type[contains(.,'SecurityTokenServiceType')]]" $fedMetadata -Namespace $ns
  if (-not $roleDescriptor)
  {
    Write-Error "The <RoleDescriptor> element with xsi:type='fed:SecurityTokenServiceType' was not found";
  }
  
  $certb64 = $roleDescriptor.Node.KeyDescriptor.KeyInfo.X509Data.X509Certificate
  
  $certb64;
}


function Enable-Auth0
    (
    [string]$auth0Domain = $(throw "Domain is required. E.g.: mycompany.auth0.com"),
    [string]$clientId = $(throw "Client id is required and it can be found in the dashboard"),
    [string]$webAppUrl = $(throw "SharePoint Web Application URL is required. E.g.: http://sp2010app"),
    [string]$identifierClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    [string[]]$claims = "Email Address|http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", # Claims to Map. Format: <DisplayName>|<ClaimType>
    [string]$certPath, # signing certificate optional
    [string[]]$additionalCertPaths  # Path to certificates in the chain
    )
{

    
  if ($additionalCertPaths) 
  {
    $additionalCertPaths = $additionalCertPaths | % { Resolve-Path $_ }
  }


  # check if SP snapin exists in the machine
  if ( (Get-PSSnapin -Name Microsoft.Sharepoint.Powershell -Registered -ErrorAction SilentlyContinue) -eq $null )
  {
      Write-Error "This PowerShell script requires the Microsoft.Sharepoint.Powershell Snap-In. Try executing it from the SharePoint 2010 server"
      exit 1;
  }

  # check if SP snapin is already loaded, if not load it
  if ( (Get-PSSnapin -Name Microsoft.Sharepoint.Powershell -ErrorAction SilentlyContinue) -eq $null )
  {
      Write-Verbose "Adding Microsoft.Sharepoint.Powershell Snapin"
      Add-PSSnapin Microsoft.Sharepoint.Powershell
  }

  # check if running as Admin
  $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) 
  {
      Write-Error "This PowerShell script requires Administrator privilieges. Try opening a PowerShell console by doing right click -> 'Run as Administrator'"
      exit 1;
  }

  # check if the user is SPShell Admin
  if ( (Get-SPShellAdmin -ErrorAction SilentlyContinue) -eq $null )
  {
      $error = "This PowerShell script requires priviliege to execute SharePoint CmdLets. Try adding the user '$($currentPrincipal.Identity.Name)' as SPShellAdmin.
                  To do this run the following command Add-SPShellAdmin $($currentPrincipal.Identity.Name)"
      Write-Error $error
      exit 1;
  }

  $realm = "urn:$clientId";
  $signInUrl = "https://$auth0Domain/wsfed"
  $fedMetadataUrl = "http://$auth0Domain/wsfed/$clientId/FederationMetadata/2007-06/FederationMetadata.xml"
  $fedMetadata = GetFederationMetadata($fedMetadataUrl)
  GetCertificate($fedMetadata) | Set-Content auth0.cer

  $certPath = Resolve-Path "auth0.cer"

  # check if the application exists
  Write-Verbose "Check App exists"

  if (-not $webAppUrl.EndsWith("/")) { $webAppUrl += "/" }
  $webApp = Get-SPWebApplication | where { $_.Url -eq $webAppUrl }
  if ($webApp -eq $null) {
    $apps = ""
    Get-SPWebApplication | foreach { $apps = $apps + "`r`n Name: " + $_.DisplayName + " Url: " + $_.Url; }
    $error = "There is no SharePoint application at this url '$webAppUrl'. The existing applications are: `r`n $apps" 
          Write-Error $error
          exit;     
  }

  Write-Verbose "App exists"

  $reservedClaimTypes = @("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
  foreach ($c in $claims) {
    $ct = $c.Split("|")[1];
    if ($reservedClaimTypes -contains $ct) {
      $error = "SharePoint reserved claim type $ct can't be used."
            Write-Error $error
            exit 1; 
    }
  }

  $certs = @()
  $signingCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
  $tempCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
  $certs += $tempCert
  Write-Verbose "certs: $certs"

  while ($tempCert.Issuer -ne $tempCert.Subject) {
    $rootCertFound = $false
    foreach ($additionalCertPath in $additionalCertPaths) {
      $additionalCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($additionalCertPath)
      if ($additionalCert.Subject -eq $tempCert.Issuer) {
        $rootCertFound = $true
        break
      }
    }
    
    if (-not $rootCertFound) {
      $error = "The certificate trust chain is incomplete.
                    The certificate with the following SubjectName: $($tempCert.Issuer) was not found on the additional certificates parameter.
                    Make sure you are including the whole trust chain path public keys in the additionalCertPaths parameter"
      Write-Error $error
          exit
    }
    
    $certs += $additionalCert
    $tempCert = $additionalCert
  } 

  $mappings = @()

  foreach ($newClaimMapping in $claims) {
      $displayName = $newClaimMapping.Split("|")[0]
      $claimType = $newClaimMapping.Split("|")[1]
      Write-Verbose "Claim: $displayName | $claimType"
      
      $mappings += New-SPClaimTypeMapping -IncomingClaimType $claimType -IncomingClaimTypeDisplayName $displayName -SameAsIncoming
  }

  # Add Auth0-STS
  $spti = $null
  $existingIdP = Get-SPTrustedIdentityTokenIssuer

  if ($existingIdP -ne $null) {
      foreach ($idp in $existingIdP) {
          if ($idp.Name -eq "Auth0") {
              $spti = $idp
              break
          }
      }
  }

  if ($spti -eq $null) {    
      Write-Verbose "Creating the SPTrustedIdentityTokenIssuer"
      Write-Verbose "New-SPTrustedIdentityTokenIssuer -Name 'Auth0' -Description 'Auth0 Federation Hub' -Realm '$realm' -ImportTrustCertificate '$($signingCert.SubjectName.Name)' -SignInUrl '$signInUrl' -ClaimsMappings '$(foreach ($m in $mappings) { $m.DisplayName + '|' + $m.InputClaimType } )' -IdentifierClaim '$identifierClaimType"
      $spti = New-SPTrustedIdentityTokenIssuer -Name "Auth0" -Description "Auth0 Federation Hub" -Realm $realm -ImportTrustCertificate $signingCert -SignInUrl $signInUrl -ClaimsMappings $mappings -IdentifierClaim $identifierClaimType
  }

  else {
    
    Write-Verbose "SPTrustedIdentityTokenIssuer 'Auth0' already exists"
      $spti = Get-SPTrustedIdentityTokenIssuer "Auth0"

    # check that none of the mappings in the parameters compromises the existing ones

    $previouslyInexistentMappings = @()

    foreach ($claimMapping in $mappings) {
      $isRepeated = $false
      foreach ($claimTypeInformation in $spti.ClaimTypeInformation) {   
        Write-Verbose "SPTrustedIdentityTokenIssuer ClaimTypeInformation: DisplayName:'$($claimTypeInformation.DisplayName)' ClaimType:'$($claimTypeInformation.InputClaimType)"

              if($claimMapping.DisplayName -eq $claimTypeInformation.DisplayName) {
          if ($claimMapping.InputClaimType -ne $claimTypeInformation.InputClaimType){       
            Write-Verbose "ClaimType '$($claimTypeInformation.DisplayName)' Already in use"
          }
                  
          $isRepeated = $true
        }
        else {
          if($claimMapping.InputClaimType -eq $claimTypeInformation.InputClaimType){
            Write-Verbose "ClaimType '$($claimTypeInformation.DisplayName)' already in use"
          }           
        } 
      }
      if ($isRepeated -ne $true) {
        $previouslyInexistentMappings += $claimMapping
      }
    }

    foreach ($claimMapping in $previouslyInexistentMappings) {
          Write-Verbose "Adding ClaimType $claimMapping.InputClaimType"
      $spti.ClaimTypes.Add($claimMapping.InputClaimType)
      $spti.Update()
      Add-SPClaimTypeMapping -Identity $claimMapping -TrustedIdentityTokenIssuer $spti
      Write-Verbose "Added claim mapping: '$($claimMapping.DisplayName)' '$($claimMapping.InputClaimType)'"
    }

      $isStsConfigured = $false
    
      $existingAuthProv = Get-SPAuthenticationProvider -webapplication $webApp -zone "Default"
    
      foreach ($authProv in $existingAuthProv) {
          if ($authProv.LoginProviderName -eq "Auth0") {
              Write-Verbose "Auth0 is configured for $webAppUrl"
          $isStsConfigured = $true
              break
          }
      }

    $spti.SigningCertificate = $signingCert
      $spti.Update()  
    
    $spti | Set-SPTrustedIdentityTokenIssuer -SignInUrl $signInUrl

      $uri = New-Object System.Uri($webAppUrl)
          
      if (-not $isStsConfigured) 
      {
          Write-Verbose "Adding ProviderRealms '$realm' to the webapp '$uri'" 
          if ($spti.ProviderRealms.ContainsKey($webApp.Url)) { $spti.ProviderRealms.Remove($webApp.Url) } 
      }
      else
      {
          Write-Verbose "ProviderRealms check for key -> '$($webApp.Url)' and not value -> '$realm'" 
          $realmChanged = $spti.ProviderRealms.ContainsKey($webApp.Url) -and -not $spti.ProviderRealms.ContainsValue($realm);
          Write-Verbose "Realm changed: '$($realmChanged)'" 
          if ($realmChanged) { $spti.ProviderRealms.Remove($webApp.Url) }
           
      }
      
      $spti.DefaultProviderRealm = $realm;
      try {
    $spti.ProviderRealms.add($uri, $realm)
    $spti.Update()  
  }
  catch {}
}

  # Update Web App to use Claims AuthN

  Write-Verbose "Checking that $webAppUrl has claims-based authentication configured"
  $webApp = Get-SPWebApplication | where { $_.Url -eq $webAppUrl }  
  if ($webApp.UseClaimsAuthentication -ne 1) {

      Write-Verbose "Configuring claims-based auth to $webAppUrl"
      $webApp.UseClaimsAuthentication = 1
      $webApp.Update()
      $webApp.ProvisionGlobally()
  }

  # Add auth provider to WebApp.

  if ($isStsConfigured -ne $true) {
      [array] $authProviders = $existingAuthProv

      Write-Verbose "Adding Auth0 to $webAppUrl existing auth provider. THIS CAN TAKE MINUTES. Please wait..."
      Set-SPWebApplication $webApp -AuthenticationProvider ($authProviders + $spti) -zone "Default"
  }

  # Add STS certificate and its certificate chain as trusted.
  $existingTrustedRootAuth = Get-SPTrustedRootAuthority
  foreach ($tempCert in $certs) {
    $certName = ([regex]'CN=([^,]+)').matches($tempCert.Subject) | foreach {$_.Groups[1].Value}
    Write-Verbose "Checking if certificate $certName exists in SP rusted root"  
              
      $trustedRootAuthExists = $false
    foreach ($trustedRootAuth in $existingTrustedRootAuth) {
      if ($trustedRootAuth.Name -eq $certName) {
          
        Write-Verbose "Certificate $certName exists in SP rusted root"  
              $trustedRootAuthExists = $true
        break
      }
    }
    if ($trustedRootAuthExists -ne $true) {
          Write-Verbose "Certificate $certName does not exist in SP trusted root. Adding certificate $certName to SP trusted root"
      New-SPTrustedRootAuthority -name $certName -Certificate $tempCert
    }
  }

  # Configure the STS to use session cookies
  # $config = Get-SPSecurityTokenServiceConfig
  # $config.UseSessionCookies = "True"
  # $config.Update()

  $loginPageFolder =  "$env:ProgramFiles\Common Files\Microsoft Shared\Web Server Extensions\14\TEMPLATE\IDENTITYMODEL\LOGIN"

  if (-not (Test-Path($loginPageFolder)))
  {
      Write-Error "The SharePoint 2010 folder '$loginPageFolder' could not be found"
      exit;
  }

  Get-Content .\login.aspx | foreach { $_ -replace "client=[^&]*", "client=$clientId" } | Set-Content .\auth0.aspx

  Copy-Item auth0.aspx "$loginPageFolder\auth0.aspx"

  $settings = $webApp.IisSettings.get_item("Default");
  $settings.ClaimsAuthenticationRedirectionUrl = "~/_login/auth0.aspx";
  $webApp.Update();

  $webConfigPath = [io.path]::combine($settings.Path.FullName, "web.config");
  $webconfig = [xml](get-content $webConfigPath);
  $webconfig.Save($webConfigPath + ".backup");
  $webconfig.configuration.'system.web'.authentication.forms.loginUrl = "~/_login/auth0.aspx"
  $webconfig.Save($webConfigPath);  


  # Cleanup
  Remove-PSSnapin Microsoft.Sharepoint.Powershell

  Write-Host "SharePoint Web Application '$webAppUrl' configured successfully with Auth0."
}

function Disable-Auth0
    (
    [string]$webAppUrl = $(throw "SharePoint Web Application url is required. E.g.: http://blah")
    )
{
    
  # check if SP snapin exists in the machine
  if ( (Get-PSSnapin -Name Microsoft.Sharepoint.Powershell -Registered -ErrorAction SilentlyContinue) -eq $null )
  {
      Write-Error "This PowerShell script requires the Microsoft.Sharepoint.Powershell Snap-In. Try executing it from the SharePoint 2010 server"
      exit 1;
  }

  # check if SP snapin is already loaded, if not load it
  if ( (Get-PSSnapin -Name Microsoft.Sharepoint.Powershell -ErrorAction SilentlyContinue) -eq $null )
  {
      Write-Verbose "Adding Microsoft.Sharepoint.Powershell Snapin"
      Add-PSSnapin Microsoft.Sharepoint.Powershell
  }

  # check if running as Admin
  $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -eq $false) 
  {
      Write-Error "This PowerShell script requires Administrator privilieges. Try opening a PowerShell console by doing right click -> 'Run as Administrator'"
      exit 1;
  }

  # check if the user is SPShell Admin
  if ( (Get-SPShellAdmin -ErrorAction SilentlyContinue) -eq $null )
  {
      $error = "This PowerShell script requires priviliege to execute SharePoint CmdLets. Try adding the user '$($currentPrincipal.Identity.Name)' as SPShellAdmin.
                  To do this run the following command Add-SPShellAdmin $($currentPrincipal.Identity.Name)"
      Write-Error $error
      exit 1;
  }

# check if the application exists
if (-not $webAppUrl.EndsWith("/")) { $webAppUrl += "/" }
$webApp = Get-SPWebApplication | where { $_.Url -eq $webAppUrl }
if ($webApp -eq $null) {
  $apps = ""
  Get-SPWebApplication | foreach { $apps = $apps + "`r`n Name: " + $_.DisplayName + " Url: " + $_.Url; }
  $error = "There is no SharePoint application at this url '$webAppUrl'. The existing applications are: `r`n $apps" 
        Write-Error $error
        exit;     
}
  $windows = New-SPAuthenticationProvider

  Set-SPWebApplication $webApp -AuthenticationProvider $windows -zone "Default"

  $all = Get-SPTrustedIdentityTokenIssuer
  if (-not($all -eq $null)) {
  $spti = Get-SPTrustedIdentityTokenIssuer "Auth0" 
  if (-not($spti -eq $null)) { $spti | Remove-SPTrustedIdentityTokenIssuer; }
  }

  Write-Host "Auth0 has been uninstalled from SharePoint Web Application '$webAppUrl'"

  $settings = $webApp.IisSettings.get_item("Default");
  $settings.ClaimsAuthenticationRedirectionUrl = "";
  $webApp.Update();

  $source = [io.path]::combine($settings.Path.FullName, "web.config")
  $dest = [io.path]::combine($settings.Path.FullName, "web.config.auth10")
  copy-item $source $dest
  $webConfigPath = [io.path]::combine($settings.Path.FullName, "web.config");
  $webconfig = [xml](get-content $webConfigPath);
  $webconfig.configuration.'system.web'.authentication.forms.loginUrl = "~/_login/default.aspx"
  $webconfig.Save($webConfigPath);  

  Write-Host "The login page now is the default page."

  # Cleanup
  Remove-PSSnapin Microsoft.Sharepoint.Powershell
}

Export-ModuleMember Enable-Auth0
Export-ModuleMember Disable-Auth0