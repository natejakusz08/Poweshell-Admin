  $continue = $true
while ($continue) {
    #Write-Host "'n'n'n" # adds three blank lines
    Write-Host "                                                                     "
    Write-Host "====================================================================="
    Write-Host "     Microsoft Software and Systems Academy Carpe-Schema Menu        "
    Write-Host "====================================================================="
    Write-Host "                                  "
    Write-Host "1. Disable an AD user account    "
    Write-Host "                                  "
    Write-Host "2. Enable an AD user account "
    Write-Host "                                  "
    Write-Host "3. Check for locked AD user accounts "
    Write-Host "                                  "
    Write-Host "4. Unlock an AD user account "
    Write-Host "                                  "
    Write-Host "5. Reset AD user account password "
    Write-Host "                                  "
    Write-Host "6. Identify accounts without logins >90 days "
    Write-Host "                                  "
    Write-Host "7. Disable accounts without logins >90 days "
    Write-Host "   "
    Write-Host "8. Add New Organizational Unit OU"
    Write-Host "   "  
    Write-Host "X. Exit this menu                 "
    Write-Host "                                  "
    $choice = Read-Host  "Enter selection"
    switch ($choice) {
        "1" {
	If ($termuser -eq "")
	{ $termuser = (Read-Host "Enter username")
	}
	$termuser = Read-Host "Enter username:"
	$fullname = (Get-Aduser -Identity $termuser).Name
	$Answer = Read-Host "$fullname will be disabled. Is this the information you want to use (Y/N)"
	If ($Answer.ToUpper() -ne "Y")
	{ Write-Host "`n`nOK.  Please rerun the script and reenter the data correctly.`n"
	Break
	}
	Write-Output "Disabling account for $termuser"
	Disable-ADAccount -Identity $termuser          
        }
        "2" {
	If ($ENuser -eq "")
	{ $ENuser = (Read-Host "Enter username")
	}
	$ENuser = Read-Host "Enter username"
	$fullname = (Get-Aduser -Identity $ENuser).Name
	$Answer = Read-Host "$fullname will be enabled. Is this the information you want to use (y/N)"
	If ($Answer.ToUpper() -ne "Y")
	{ Write-Host "`n`nOK.  Please rerun the script and reenter the data correctly.`n"
	Break
	}
	Write-Output "Enable account for $ENuser"
	Enable-ADAccount -Identity $ENuser
        }
        "3" {        
	  Search-ADAccount -LockedOut | Select-Object Name, SamAccountName, Userprincipalname | Out-GridView
        }
        "4" {    
	If ($unlockuser -eq "")
	{ $unlockuser = (Read-Host "Enter username")
	}
	$unlockuser = Read-Host "Enter username:"
	$fullname = (Get-Aduser -Identity $unlockuser).Name
	$Answer = Read-Host "Do you want to unlock the account for $fullname ? (y/N)"
	If ($Answer.ToUpper() -ne "Y")
	{ Write-Host "`n`nOK.  Please rerun the script and reenter the data correctly.`n"
	Break
	}
	Write-Output "Unlocking the account for $unlockuser"
	Unlock-ADAccount -Identity $unlockuser
        }
        "5" {
	If ($Passuser -eq "")
	{ $Passuser = (Read-Host "Enter username")
	}
	$Passuser = Read-Host "Enter username"
	$fullname = (Get-Aduser -Identity $Passuser).Name
	$Answer = Read-Host "Reset $fullname password? (y/N)"
	If ($Answer.ToUpper() -ne "Y")
	{ Write-Host "`n`nOK.  Please rerun the script and reenter the data correctly.`n"
	Break
	}
	$password = Read-Host "Enter password"
	Write-Output "Resetting password for $Passuser"
	Set-ADAccountPassword -Identity $Passuser -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$Password" -Force)
        }
        "6" {
	Write-Output "Currently exporting to c:unusedaccounts.csv"       
	Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 | ?{$_.enabled -eq $true} | %{Get-ADUser $_.ObjectGuid} | select name, givenname, surname, Userprincipalname  | export-csv c:unusedaccounts.csv -NoTypeInformation
	Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 | ?{$_.enabled -eq $true} | %{Get-ADUser $_.ObjectGuid} | select name, givenname, surname, Userprincipalname  | out-gridview
        }
        "7" {
	Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 | ?{$_.enabled -eq $true} |  Disable-ADAccount
        }
        "8" {
    function CreateOU {
    Param([string]$Name)}
    $name = Read-host “enter OU Name”
    #Format variables into valid Distinguished Name.
    $DistinguishedName = "OU=$Name,dc=adatum,dc=com"
    #Check to see if OU already exists.
    try {
    Get-ADOrganizationalUnit -Identity $DistinguishedName | Out-Null
    Write-Host "CreateOU - OU Already Existed: $DistinguishedName"
    }
    #Create OU if does not exist
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    Write-Host "CreateOU - Creating new OU: $DistinguishedName"
    New-ADOrganizationalUnit -Name $Name -Path "dc=adatum,dc=com"
    Write-Host "CreateOU - OU Created: $DistinguishedName"
    } 
    }       
     "X" {
	            $continue = $false
	        }
               default {
            Write-Host "'n'n ** Unknown Selection **" -ForegroundColor red -BackgroundColor white
        }
    }
}
