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

$Password = ( ConvertTo-SecureString "Disturbed1" -AsPlainText -Force )
$Credential = New-Object System.Management.Automation.PSCredential ("Administrator", $Password)
$ComputerName = "SERVER2022"
$Temp = $true
	
while($Object -ne 'Exit'){
	
	cls
	Write-Host "Hello and Welcome to the Active Directory Management Tool"
	Write-Host " "
	Write-Host "What would you like to do?"
	Write-Host "*PassReset*    Password Reset"
	Write-Host "*DisableUser*  Disable User Account"
	Write-Host "*EnableUser*   Enable User Account"
	Write-Host "*Reports*      Enter Reports Menu"
	Write-Host "Type Exit at any time to quit"
	Write-Host " "
	$Object = Read-Host -Prompt 'Enter Option here'
	#Write-Host "$Temp"
	
    Switch ($Object)
    {
        'PassReset'
		{
		    while($Temp)
			{
				cls
				Write-Host "**Password Reset**"
				Write-Host " "
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
				Write-Host " "
				
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
							Write-Host " "
							break
					    }
					
				    }                
                }
                }				
			}
			$Temp = $true
			break
		}
		'DisableUser'
		{
			while($Temp)
			{
				cls
				Write-Host "**Disable User**"
				Write-Host " "
				#Write-Host "$Temp"
				$UserName = Read-Host -Prompt 'Enter Username'
			    $Temp = Get-Valid -info $userName
				$switchPick = $true
				
				if ($Temp)
			    {		
				    Invoke-Command -ComputerName SERVER2022 -ArgumentList $UserName -Credential ($Credential) -ScriptBlock { Set-ADUser $args[0] -Enabled $false }
				
				    Write-Host " "
				    Write-Host "Domain Account $UserName has been Disabled, Notify Administrator to ReEnable"
				    Write-Host " "
				}
				
				if ($userName -eq 'Exit')
                {
					$Object = $userName
                }
				else
				{			
                Write-Host "Would you like to disable another account?"
                Write-Host "*Reset*  disable another account"
                Write-Host "*Return* return to main menu"
                Write-Host "*Exit*   exit the application"
				Write-Host " "
				
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
							Write-Host " "
							break
					    }
					
				    }                
                }
				}
			}
			$Temp = $true
            break			
		}
        'EnableUser'
        {
            while($Temp)
			{
				cls
				Write-Host "**Enable User**"
				Write-Host " "
				#Write-Host "$Temp"
				$UserName = Read-Host -Prompt 'Enter Username'
			    $Temp = Get-Valid -info $userName
				$switchPick = $true
				
				if ($Temp)
				{
					Invoke-Command -ComputerName SERVER2022 -ArgumentList $UserName -Credential ($Credential) -ScriptBlock { Set-ADUser $args[0] -Enabled $true }
				
				    Write-Host " "
				    Write-Host "Domain Account $UserName has been Enabled"
				    Write-Host " "
				}
				
				if ($userName -eq 'Exit')
                {
					$Object = $userName
                }
				else
				{			
                Write-Host "Would you like to disable another account?"
                Write-Host "*Reset*  disable another account"
                Write-Host "*Return* return to main menu"
                Write-Host "*Exit*   exit the application"
				Write-Host " "
				
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
							Write-Host " "
							break
					    }
					}
					
				}
				}
			}
            break
        }			
		default
		{
			Write-Host "Incorrect Answer, please try again!"
			Write-Host " "
			break
		}	
    }	
}