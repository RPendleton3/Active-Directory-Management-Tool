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
	Write-Host "*Reset*  reset current operation"
    Write-Host "*Return* return to main menu"
    Write-Host "*Exit*   exit the application"
	Write-Host " "
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
	Write-Host "*AddUser*      Create New Domain User"
	Write-Host "*RemoveUser*   Delete Domain User"
	Write-Host "*AddGroup*     Add User to Group"
	Write-Host "*RemoveGroup*  Remove User from Group"
	Write-Host "*PassReset*    Password Reset"
	Write-Host "*DisableUser*  Disable User Account"
	Write-Host "*EnableUser*   Enable User Account"
	Write-Host "*Reports*      Enter Reports Menu"
	Write-Host "*OrgUnits*     Modify Organizational Units"
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
			$Temp = $true
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
				Write-Host "An Account has been created for $UserName with a base password of P@ssw0rd01"
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
		'RemoveUser'
		{
			while($Temp)
			{
				cls
				Write-Host "**Delete Domain User Account**"
				Write-Host " "
				#Write-Host "$Temp"			    
				$UserName = Read-Host -Prompt 'Enter Username'
				$Temp = Get-Valid -info $userName
				$switchPick = $true
				
				if ($Temp)
				{
				    Invoke-Command -ComputerName $ComputerName -ArgumentList $UserName -Credential ($Credential) -ScriptBlock { Remove-ADUser $args[0]}
					
					Write-Host " "
				    Write-Host "Domain Account $UserName has been Removed"
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
		'OrgUnits'
		{
			while($Temp)
			{
				cls
				Write-Host "**Modify Organizational Units**"
				Write-Host " "
				#Write-Host "$Temp"
			    $UserName = Read-Host -Prompt 'Enter Username'
			    $Temp = Get-Valid -info $userName
				$switchPick = $true
                $switchValid = $true				
                
                if ($Temp)
			    {		
                    $UserData = Get-ADUser -Identity $UserName
				    Get-ADUser -Identity "$UserName" | Format-Table Name,DistinguishedName
				    Write-Host "Enter the Name of the Organizational Unit for the User"
				    Write-Host " "
                    Write-Host "Domain Controllers"
                    Write-Host "Administrator"
                    Write-Host "Management"
                    Write-Host "Type Exit at any time to quit"
				    Write-Host " "				   
					
					While ($switchValid)
					{
						$OUobject = Read-Host -Prompt 'Enter Organizational Unit'
					Switch ($OUobject)
					{
						'Domain Controllers'
						{
							Invoke-Command -ComputerName SERVER2022 -ArgumentList $UserData.DistinguishedName -Credential ($Credential) -ScriptBlock {Move-ADObject -Identity $args[0] -TargetPath "OU=Domain Controllers,DC=XYZ,DC=local"}
							Get-ADUser -Identity "$UserName" | Format-Table Name,DistinguishedName	
                            $switchValid = $false							
						    break
						}
						'Administrator'
						{
							Invoke-Command -ComputerName SERVER2022 -ArgumentList $UserData.DistinguishedName -Credential ($Credential) -ScriptBlock {Move-ADObject -Identity $args[0] -TargetPath "OU=Administrator,OU=Domain Controllers,DC=XYZ,DC=local"}
							Get-ADUser -Identity "$UserName" | Format-Table Name,DistinguishedName	
                            $switchValid = $false	
							break
						}
						'Management'
						{
							Invoke-Command -ComputerName SERVER2022 -ArgumentList $UserData.DistinguishedName -Credential ($Credential) -ScriptBlock {Move-ADObject -Identity $args[0] -TargetPath "OU=Management,OU=Domain Controllers,DC=XYZ,DC=local"}
							Get-ADUser -Identity "$UserName" | Format-Table Name,DistinguishedName	
                            $switchValid = $false	
							break
						}
						'Exit'
						{
							$userName = $OUobject
							$switchValid = $false
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
				}
				if ($userName -eq 'Exit')
                {
					$Object = $userName
					$Temp = $false
                }
				else
				{			
                Write-Host "Would you like to modify another Organizational Unit?"
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
		'AddGroup'
		{
			cls
            Write-Host " "
            Write-Host "Creating Active Groups List, Please Wait..."
            Invoke-Command -ComputerName $ComputerName -Credential ($Credential) -ScriptBlock { Get-ADGroup -Filter * |Select Name | Export-CSV -path "C:\NetworkStorage\RPendleton\Active_Groups.csv" -NoTypeInformation}
            $csv = Import-Csv -Path \\10.0.0.38\RPendletonShare\Active_Groups.csv  
            Remove-Item -Path \\10.0.0.38\RPendletonShare\Active_Groups.csv	
	        $counter = $csv.Count
			
			while($Temp)
			{
				cls
	            Write-Host "     **Add User to Groups**    "	
	            Write-Host "*Type Exit at any time to quit*"
	            Write-Host " "
	            $UserName = Read-Host -Prompt 'Enter Username'
	            $Temp = Get-Valid -info $userName
	            $switchPick = $true
	            $switchValid = $true
				
				if ($Temp)
				{
					cls
                    Write-Host "Domain User $UserName is part of these groups"
		            Write-Host " "
		            ([ADSISEARCHER]"samaccountname=$($UserName)").Findone().Properties.memberof -replace '^CN=([^,]+).+$','$1'  
		            Write-Host " "
					
					While ($switchValid)
					{
						$truth = $true
			            $valid = $true
			            Write-Host " "
		                Write-Host "     **Add User to Groups**    "
		                Write-Host " "
		                Write-Host "*Show*     Show current list of Groups"
		                Write-Host "*Reset*    Reset current opperation"
		                Write-Host "*Return*   Return to main menu"
		                Write-Host "*Exit*     Exit the application"
			            Write-Host " "
			            $UserData = Read-Host -Prompt 'Enter Group'
						Switch ($UserData)
						{
							'Show'
				            {
					            cls
					            $csv.name
					            break
				            }
							'Reset'
							{
								$switchValid = $false
					            $Temp = $false
					            break
							}
							'Return'
							{
								$switchValid = $false
					            $Temp = $false
					            break
							}
							'Exit'
							{
								$UserName = $UserData								
					            $switchValid = $false
					            $Temp = $false
					            break
							}
							Default
							{
								$I = 0
								while($valid)
                                {
				                    if ($csv.name[$I] -eq $UserData)
	                                { 
		                                $current = $csv.name[$I]
		                                #Write-Host "$UserName is $current"
		                                $valid = $false	
										$switchValid = $false
										$Temp = $false
										Invoke-Command -ComputerName $ComputerName -ArgumentList $UserName, $UserData -Credential ($Credential) -ScriptBlock {Add-ADGroupMember -Identity $args[1] -Members $args[0]}
	                                }
	                                else
	                                {
		                                $current = $csv.name[$I]
		                                #Write-Host "$UserName is not $current"
		                                $I++
		                                if ($I -eq $counter)
		                                {
			                                $valid = $false
						                    $truth = $false
		                                }
	                                }
							    }
								if(!$truth)
				                {
                                    cls
                                    Write-Host "Domain User $UserName is part of these groups"
		                            Write-Host " "
		                            ([ADSISEARCHER]"samaccountname=$($UserName)").Findone().Properties.memberof -replace '^CN=([^,]+).+$','$1'  
		                            Write-Host " "					
					                Write-Host "$UserData was not found, please try again"
				                }
								break
						    }   
					    }
						$UserName = $UserData
				    }
			    }				
				if ($UserName -eq 'Exit')
                {
					$Object = $userName
					$Temp = $false
                }
				elseif($UserName -eq 'Return')
				{
					
				}
				elseif($UserName -eq 'Reset')
	            {
		            $Temp = $true
	            }
				else
				{
			    cls
				Write-Host "User $Username is now part of the following groups"
				Write-Host " "
                ([ADSISEARCHER]"samaccountname=$($UserName)").Findone().Properties.memberof -replace '^CN=([^,]+).+$','$1' 					
				Write-Host " "
                Write-Host "Would you like to add more users to groups?"
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
		'RemoveGroup'
		{
			
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