Function Get-Valid{
    param(
	$info
	)
	
	$userData = $info -ne 'exit'
	#Write-Host "$userData"
	$userData = ($userData) -and ($info -ne 'return')	
	#Write-Host "$userData"
	
	return $userData
}

$Password = ( ConvertTo-SecureString "P@ssword01" -AsPlainText -Force )
$Credential = New-Object System.Management.Automation.PSCredential ("Administrator", $Password)
$ComputerName = "SERVER2022"
$Temp = $true
	
while($Object -ne 'Exit'){
	
	Write-Host "Hello and Welcome to the Active Directory Management Tool"
	Write-Host "What would you like to do?"
	Write-Host "1. Password Reset *PassReset*"
	#Write-Host "2. Disable User Account *DisableUser*"
	Write-Host "Type Exit at any time to quit"
	$Object = Read-Host -Prompt 'Enter Option here'
	
    Switch ($Object)
    {
        'PassReset'
		{
		    while($Temp)
			{
				#Write-Host "$Temp"
			    $UserName = Read-Host -Prompt 'Enter Username'
			    $Temp = Get-Valid -info $userName
				$switchPick = $true
				
                if ($Temp)
			    {			
			        Invoke-Command -ComputerName $ComputerName -ArgumentList $UserName -Credential ($Credential) -ScriptBlock { Set-ADAccountPassword -Identity $args[0] -NewPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd01" -Force) -Reset}
                    Invoke-Command -ComputerName $ComputerName -ArgumentList $UserName -Credential ($Credential) -ScriptBlock { Set-ADUser $args[0] -ChangePasswordAtLogon $true }
			
			        Write-Host " "
			        Write-Host "The password has been set to P@ssw0rd01 for user $UserName"
                    Write-Host "Alert user they will be prompt to create a new password at logon"
			        Write-Host " "	
				}
				
				if ($userName -eq 'Exit')
                {
					$Object = $userName
                }
                else
				{			
                Write-Host "Would you like to reset another password?"
                Write-Host "*Reset*  reset another password"
                Write-Host "*Return* return to main menu"
                Write-Host "*Exit*   exit the application"
				
				while ($switchPick)
				{
                $userName = Read-Host -Prompt 'Enter Choice'
				
				
				    switch($userName)
				    {
					    'Reset'
					    {
						    $Temp = $true
							$switchPick = $false
						    #Write-Host "$Temp"
						    break
					    }
					    'Return'
					    {
					        $Temp = $false
							$switchPick = $false
						    #Write-Host "$Temp"
						    break
					    }
					    'Exit'
					    {
						    $Temp = $false
							$switchPick = $false
					        $Object = $userName
						    break
					    }
					    default
					    {
							$switchPick = $true
						    Write-Host "Incorrect Answer, please try again!"
							break
					    }
					
				    }                
                }
                }				
			}
			break
		}
    }	
}
