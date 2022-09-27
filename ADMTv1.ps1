$Password = ( ConvertTo-SecureString "P@ssw0rd01" -AsPlainText -Force )
$Credential = New-Object System.Management.Automation.PSCredential ("Administrator", $Password)

    Write-Host "Hello and Welcome to the Active Directory Management Tool"
	Write-Host "What would you like to do?"
	Write-Host "1. Password Reset *PassReset*"
	Write-Host "2. Disable User Account *DisableUser*"
	Write-Host "Type Exit at any time to quit"
	$Object = Read-Host -Prompt 'Enter Option here'
 
while($Object -ne 'Exit'){  
	
	    if ($Object -eq 'PassReset')
		{
		    $UserName = Read-Host -Prompt 'Enter Username'
			
            if ($UserName -ne 'Exit')
			{			
			    Invoke-Command -ComputerName SERVER2022 -ArgumentList $UserName -Credential ($Credential) -ScriptBlock { Set-ADAccountPassword -Identity $args[0] -NewPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd01" -Force) -Reset}
                Invoke-Command -ComputerName SERVER2022 -ArgumentList $UserName -Credential ($Credential) -ScriptBlock { Set-ADUser $args[0] -ChangePasswordAtLogon $true }
			
			    Write-Host " "
			    Write-Host "The password has been set to P@ssw0rd01 for user $UserName"
                Write-Host "Alert user they will be prompt to create a new password at logon"
			    Write-Host " "	
			}			
		}
		if ($Object -eq 'DisableUser')
		{
			$UserName = Read-Host -Prompt 'Enter Username'
			
			if ($UserName -ne 'Exit')
			{
				Invoke-Command -ComputerName SERVER2022 -ArgumentList $UserName -Credential ($Credential) -ScriptBlock { Set-ADUser $args[0] -Enabled $false }
				
				Write-Host " "
				Write-Host "Domain Account $UserName has been Disabled, Notify Administrator to ReEnable"
				Write-Host " "
			
			}
		
		}
	
    if ($UserName -ne 'Exit')
	{	
	    Write-Host "What would you like to do Next?"	
	    Write-Host "1. Password Reset *PassReset*"
		Write-Host "2. Disable User Account *DisableUser*"
	    Write-Host "**Type Exit to Quit"
	    $Object = Read-Host -Prompt 'Enter Option here'
	}
	else
	{
		$Object = $Username
	}
}
