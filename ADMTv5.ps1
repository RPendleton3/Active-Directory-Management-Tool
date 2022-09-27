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

Function CheckIfValid{
	param(
	    $Data
	)
	
	$value = " " | Select-Object -Property Temp,switchPick,Object
	switch($Data)
	{
	    'Reset'
	    {
			$value.Temp = $true
			$value.switchPick = $false
			#Write-Host "$Temp"
			break
		}
		'Return'
		{
		    $value.Temp = $false
			$value.switchPick = $false
			#Write-Host "$Temp"
			break
		}
		'Exit'
		{
			$value.Temp = $false
			$value.switchPick = $false
			$value.Object = $Data
		    break
		}
		default
		{
			$value.switchPick = $true
			Write-Host "Incorrect Answer, please try again!"
			Write-Host " "
			break
		}
					
	}
	return $value	
}

Function DisplayMenuOptions{
	Write-Host "*Reset*  create another user"
    Write-Host "*Return* return to main menu"
    Write-Host "*Exit*   exit the application"
	Write-Host " "
}

$Password = ( ConvertTo-SecureString "P@ssw0rd01" -AsPlainText -Force )
$Credential = New-Object System.Management.Automation.PSCredential ("Administrator", $Password)
$ComputerName = "SERVER2022"
$Temp = $true
	
while($Object -ne 'Exit'){
	
	cls
	Write-Host "Hello and Welcome to the Active Directory Management Tool"
	Write-Host " "
	Write-Host "What would you like to do?"
	Write-Host "*AddUser*      Create New Domain User"
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
                DisplayMenuOptions
				
				while ($switchPick)
				{
                $userName = Read-Host -Prompt 'Enter Choice'
				$switchvalue = CheckIfValid $userName
				$Temp = $switchvalue.Temp
				$switchPick = $switchvalue.switchPick
				$Object = $switchvalue.Object				           
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
                DisplayMenuOptions
				
				while ($switchPick)
				{
                $userName = Read-Host -Prompt 'Enter Choice'
				$switchvalue = CheckIfValid $userName
				$Temp = $switchvalue.Temp
				$switchPick = $switchvalue.switchPick
				$Object = $switchvalue.Object				           
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
                DisplayMenuOptions
				
				while ($switchPick)
				{
				$userName = Read-Host -Prompt 'Enter Choice'
				$switchvalue = CheckIfValid $userName
				$Temp = $switchvalue.Temp
				$switchPick = $switchvalue.switchPick
				$Object = $switchvalue.Object					
				}
				}
			}
            break
        }
        'Reports'
        {
            break
        }
        'AddUser'
        {
            while($Temp)
			{
				cls
				Write-Host "**Create Domain User Account**"
				Write-Host " "
				#Write-Host "$Temp"			    
				$GivenName = Read-Host -Prompt 'Enter First Name'
				if($Temp)
				{
					$Temp = Get-Valid -info $GivenName
					#Write-Host "$Temp"
					
					if($Temp)
					{
					    $SurName = Read-Host -Prompt 'Enter Last Name'
						$Temp = Get-Valid -info $SurName
						#Write-Host "$Temp"
					}
				} 

                $UserName = $GivenName[0]+$SurName
                #Write-Host "$UserName"				
				$switchPick = $true				
			
			
			if ($Temp)
			{
				Invoke-Command -ComputerName $ComputerName -ArgumentList $UserName, $GivenName, $SurName -Credential ($Credential) -ScriptBlock { New-ADUser $args[0] -GivenName $args[1] -SurName $args[2] -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd01" -Force) -ChangePasswordAtLogon $true -Enabled $true }
				
				Write-Host " "
				Write-Host "An Account has been created for $GivenName $SurName with a base password of P@ssw0rd01"
                Write-Host "Remind user that on first sign in they will be prompt for a new password"
				Write-Host " "
			}
			
			if ($GivenName -eq 'Exit')
            {
			    $Object = $GivenName
            }			
			elseif ($SurName -eq 'Exit')
            {
			    $Object = $SurName
            }
			else
			{			
                Write-Host "Would you like to create another user?"                
				DisplayMenuOptions
			
			while ($switchPick)
				{
                $userName = Read-Host -Prompt 'Enter Choice'				
				$switchvalue = CheckIfValid $userName
				$Temp = $switchvalue.Temp
				$switchPick = $switchvalue.switchPick
				$Object = $switchvalue.Object				       
                }
			}
            }
        $Temp = $true
		break			
        }
        'Exit'
        {
			Write-Host "Thanks for using the Active Directory Management Tool, Have a Good Day!"
			Write-Host " "
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
