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

Function IsDataThere{
	param(
	    $Name
	)
	$check = $true
	while($check -eq $true)
	{
	if(!$Name)
	{
		Write-Host "Please Enter a value"
		$Name = Read-Host -Prompt 'Enter Input'
		$check = $true
	}
	else
	{
		$check = $false
	}
	}
	return $Name
}

Function Create_UserName{
	
	
	$value = " " | Select-Object -Property Temp,Name,Check,FName,LName
	$value.FName = Read-Host -Prompt 'Enter First Name'
	$value.FName = IsDataThere -Name $value.FName
	$value.Temp = $true
	if($Temp -eq $true)
	{
		$value.Temp = Get-Valid -info $value.FName
		#Write-Host "$Temp"
					
		if($value.Temp)
		{
		    $value.LName = Read-Host -Prompt 'Enter Last Name'
			$value.LName = IsDataThere -Name $value.LName
			$value.Temp = Get-Valid -info $value.LName
			#Write-Host "$Temp"
			$value.check = $true
		}
		else
		{
		    $value.check = $false
		}
	}
	if($value.check -eq $true)
	{
		$value.Name = $value.FName[0]+$value.LName
		$value.Temp = Get-Valid -info $value.Name		
	}
	return $value
   
}

Function Add_User_Validate{
	Invoke-Command -ComputerName $ComputerName -ArgumentList $UserName -Credential ($Credential) -ScriptBlock {Get-ADUser -Filter * | Select-Object Name | Sort-Object Name | Export-CSV -path "C:\NetworkStorage\RPendleton\Active_Users.csv" -NoTypeInformation}
	$Namecsv = Import-Csv -Path \\10.0.0.38\RPendletonShare\Active_Users.csv
	#Remove-Item -Path \\10.0.0.38\RPendletonShare\Active_Users.csv
	$value = " " | Select-Object -Property Temp,Name,Check,FName,LName
	$value.check = $true 
    $value.Temp = $true   	
	while($value.check -eq $true)
	{	
	$import = Create_UserName
	$value.Temp = $import.Temp
	$value.Check = $import.Check
	$value.Name = $import.Name
	$value.FName = $import.FName
	$value.LName = $import.LName
	if($value.Temp -eq $true)
	{
	    $I = 0
	    while($I -lt $Namecsv.count)
	    {
	        if ($Namecsv.name[$I] -eq $value.Name)
	        {
		        #Write-Host "Match"
			    $I = $Namecsv.count
                $value.check = $true			
			    #pause
	        }
		    else
		    {
			    $current = $Namecsv.name[$I]
			    #Write-Host "$current"
			    $I++  
                $value.check = $false			
			    #pause
       			
		    }
	    }
	}
	else
    {
        $value.check = $false
    }
	if($value.check -eq $true)
	{
        write-host "Username already exists, please try again!"
		write-host " "
					
    }
	}
	#Write-Host "$value"
	return $value
}

Function Validate_User{
	
	Invoke-Command -ComputerName $ComputerName -ArgumentList $UserName -Credential ($Credential) -ScriptBlock {Get-ADUser -Filter * | Select-Object Name | Sort-Object Name | Export-CSV -path "C:\NetworkStorage\RPendleton\Active_Users.csv" -NoTypeInformation}
	$Namecsv = Import-Csv -Path \\10.0.0.38\RPendletonShare\Active_Users.csv
	#Remove-Item -Path \\10.0.0.38\RPendletonShare\Active_Users.csv
	$value = " " | Select-Object -Property Name,Temp,Check
	$value.check = $true
	while($value.check -eq $true)
	{
	$value.Name = Read-Host -Prompt 'Enter Username'
	$value.Name = IsDataThere -Name $value.Name
	$value.Temp = Get-Valid -info $value.Name
	
	if($value.Temp -eq $true)
	{
	    $I = 0
	    while($I -lt $Namecsv.count)
	    {
	        if ($Namecsv.name[$I] -eq $value.Name)
	        {
		        #Write-Host "Match"
			    $I = $Namecsv.count
                $value.check = $false			
			    #pause
	        }
		    else
		    {
			    $current = $Namecsv.name[$I]
			    #Write-Host "$current"
			    $I++  
                $value.check = $true			
			    #pause
       			
		    }
	    }
	}
	else
    {
        $value.check = $false
    }
    if($value.check -eq $true)
	{
        write-host "Incorrect Username, please try again!"
		write-host " "
					
    }
    }
    return $value	
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
				Write-Host "              **Password Reset**"
				Write-Host "       *Type Exit at any time to quit*"
				Write-Host "*Type Return at any time to go back to menu*"
				Write-Host " "				
				$Validation = Validate_User
				$Username = $Validation.Name
				$Temp = $Validation.Temp
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
				elseif ($userName -eq 'Return')
				{
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
				Write-Host "               **Disable User**"
				Write-Host "       *Type Exit at any time to quit*"
				Write-Host "*Type Return at any time to go back to menu*"
				Write-Host " "
				$Validation = Validate_User
				$Username = $Validation.Name
				$Temp = $Validation.Temp
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
				elseif($UserName -eq 'Return')
				{					
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
				Write-Host "              **Enable User**"
				Write-Host "       *Type Exit at any time to quit*"
				Write-Host "*Type Return at any time to go back to menu*"
				Write-Host " "				
				$Validation = Validate_User
				$Username = $Validation.Name
				$Temp = $Validation.Temp
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
				elseif($UserName -eq 'Return')
				{					
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
				Write-Host "       **Create Domain User Account**"
				Write-Host "       *Type Exit at any time to quit*"
				Write-Host "*Type Return at any time to go back to menu*"
				Write-Host " "
				$Validation = Add_User_Validate
				$Username = $Validation.Name
				$Temp = $Validation.Temp                			
				$FName = $Validation.FName
				$LName = $Validation.LName	
                #Write-Host "$Validation"						
				$switchPick = $true				
			
			
			if ($Temp)
			{
				Invoke-Command -ComputerName $ComputerName -ArgumentList $UserName, $FName, $LName -Credential ($Credential) -ScriptBlock { New-ADUser $args[0] -GivenName $args[1] -SurName $args[2] -AccountPassword (ConvertTo-SecureString -AsPlainText "P@ssw0rd01" -Force) -ChangePasswordAtLogon $true -Enabled $true }
				
				Write-Host " "
				Write-Host "An Account has been created for $UserName with a base password of P@ssw0rd01"
                Write-Host "Remind user that on first sign in they will be prompt for a new password"
				Write-Host " "
			}
			
			if ($FName -eq 'Exit')
			{
				$Object = $Validation.FName
			}
			elseif ($LName -eq 'Exit')
			{
				$Object = $Validation.LName
			}
			elseif ($FName -eq 'Return')
			{
				
			}
			elseif ($LName -eq 'Return')
			{
				
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
				Write-Host "       **Delete Domain User Account**"
				Write-Host "       *Type Exit at any time to quit*"
				Write-Host "*Type Return at any time to go back to menu*"
				Write-Host " "
				$Validation = Validate_User
				$Username = $Validation.Name
				$Temp = $Validation.Temp
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
				elseif($UserName -eq 'Return')
				{					
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
				Write-Host "       **Modify Organizational Units**"
				Write-Host "       *Type Exit at any time to quit*"
				Write-Host "*Type Return at any time to go back to menu*"
				Write-Host " "
				$Validation = Validate_User
				$Username = $Validation.Name
				$Temp = $Validation.Temp
				$switchPick = $true
                $switchValid = $true				
                
                if ($Temp)
			    {	
				    cls
                    Write-Host "       **Modify Organizational Units**"	
                    Write-Host " "					
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
				elseif($UserName -eq 'Return')
				{					
				}
				else
				{			
                Write-Host "Would you like to modify another Organizational Unit?"
                DisplayMenuOptions
				
				while ($switchPick)
				{
                $userName = Read-Host -Prompt 'Enter Choice'
				$userName = IsDataThere -Name $userName
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
			while($Temp)
			{
				cls
	            Write-Host "            **Add User to Groups**    "	
	            Write-Host "       *Type Exit at any time to quit*"
				Write-Host "*Type Return at any time to go back to menu*"
	            Write-Host " "	            
	            $switchPick = $true
	            $switchValid = $true
				$Validation = Validate_User
				$Username = $Validation.Name
				$Temp = $Validation.Temp
				if ($Temp)
				{
				cls
                Write-Host " "
                Write-Host "Creating Active Groups List, Please Wait..."
                Invoke-Command -ComputerName $ComputerName -Credential ($Credential) -ScriptBlock { Get-ADGroup -Filter * |Select Name | Export-CSV -path "C:\NetworkStorage\RPendleton\Active_Groups.csv" -NoTypeInformation}
                $csv = Import-Csv -Path \\10.0.0.38\RPendletonShare\Active_Groups.csv  
                Remove-Item -Path \\10.0.0.38\RPendletonShare\Active_Groups.csv	
	            $counter = $csv.Count				
				Write-Host " "
                Write-Host "Creating Group Information List, Please Wait..."
	            Invoke-Command -ComputerName $ComputerName -ArgumentList $UserName -Credential ($Credential) -ScriptBlock {Get-ADPrincipalGroupMembership $args[0] |Select Name | Export-CSV -path "C:\NetworkStorage\RPendleton\User_Groups.csv" -NoTypeInformation}
	            $Usercsv = Import-Csv -Path \\10.0.0.38\RPendletonShare\User_Groups.csv
	            Remove-Item -Path \\10.0.0.38\RPendletonShare\User_Groups.csv
                $Usercounter = $Usercsv.Count               			
				}
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
						$truth2 = $true
			            $valid = $true
						$valid2 = $true
			            Write-Host " "
		                Write-Host "     **Add User to Groups**    "
		                Write-Host " "
		                Write-Host "*Show*     Show current list of Groups"
		                Write-Host "*Reset*    Reset current opperation"
		                Write-Host "*Return*   Return to main menu"
		                Write-Host "*Exit*     Exit the application"
			            Write-Host " "
			            $UserData = Read-Host -Prompt 'Enter Group'
						$UserData = IsDataThere -Name $UserData
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
								$UserName = $UserData
								$switchValid = $false
					            $Temp = $false
					            break
							}
							'Return'
							{
								$UserName = $UserData
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
										#Invoke-Command -ComputerName $ComputerName -ArgumentList $UserName, $UserData -Credential ($Credential) -ScriptBlock {Add-ADGroupMember -Identity $args[1] -Members $args[0]}
										$I = 0
										while($valid2)
										{
											if ($Usercsv.name[$I] -eq $UserData)
											{
												$I = $Usercounter
												$valid = $false
												$valid2 = $false
												$truth2 = $false
												#Write-Host "U Failed"
												#pause
											}
											else
											{
												$Usercurrent = $Usercsv.name[$I]
												#Write-Host "$UserData is not $Usercurrent"
												#pause
												$I++
												if ($I -eq $Usercounter)
		                                        {
													$switchValid = $false
													$Temp = $false
													Invoke-Command -ComputerName $ComputerName -ArgumentList $UserName, $UserData -Credential ($Credential) -ScriptBlock {Add-ADGroupMember -Identity $args[1] -Members $args[0]}
													$valid = $false
			                                        $valid2 = $false						                            
		                                        }
											}
										}
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
								if(!$truth2)
								{
									cls
                                    Write-Host "Domain User $UserName is part of these groups"
		                            Write-Host " "
		                            ([ADSISEARCHER]"samaccountname=$($UserName)").Findone().Properties.memberof -replace '^CN=([^,]+).+$','$1'  
		                            Write-Host " "					
					                Write-Host "User $UserName is already part of group $UserData, please try again"
					                Write-Host " "										
								}
								break
						    }   
					    }
						
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
                $userData = Read-Host -Prompt 'Enter Choice'
				$userData = IsDataThere -Name $userData
				$switchvalue = CheckIfValid $userData
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
			while($Temp)
			{
				cls
	            Write-Host "         **Remove User from Groups**    "	
	            Write-Host "       *Type Exit at any time to quit*"
				Write-Host "*Type Return at any time to go back to menu*"
	            Write-Host " "	            
	            $switchPick = $true
	            $switchValid = $true
				$Validation = Validate_User
				$Username = $Validation.Name
				$Temp = $Validation.Temp
				
				if ($Temp)
				{
				cls
                Write-Host " "
                Write-Host "Creating Active Groups List, Please Wait..."
                Invoke-Command -ComputerName $ComputerName -Credential ($Credential) -ScriptBlock { Get-ADGroup -Filter * |Select Name | Export-CSV -path "C:\NetworkStorage\RPendleton\Active_Groups.csv" -NoTypeInformation}
                $csv = Import-Csv -Path \\10.0.0.38\RPendletonShare\Active_Groups.csv  
                Remove-Item -Path \\10.0.0.38\RPendletonShare\Active_Groups.csv	
	            $counter = $csv.Count				
				Write-Host " "
                Write-Host "Creating Group Information List, Please Wait..."
	            Invoke-Command -ComputerName $ComputerName -ArgumentList $UserName -Credential ($Credential) -ScriptBlock {Get-ADPrincipalGroupMembership $args[0] |Select Name | Export-CSV -path "C:\NetworkStorage\RPendleton\User_Groups.csv" -NoTypeInformation}
	            $Usercsv = Import-Csv -Path \\10.0.0.38\RPendletonShare\User_Groups.csv
	            Remove-Item -Path \\10.0.0.38\RPendletonShare\User_Groups.csv
                $Usercounter = $Usercsv.Count               			
				}
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
						$truth2 = $true
			            $valid = $true
						$valid2 = $true
			            Write-Host "         **Remove User from Groups**    "	
	                    Write-Host "       *Type Exit at any time to quit*"
				        Write-Host "*Type Return at any time to go back to menu*"
	                    Write-Host " "		                
		                Write-Host "*Reset*    Reset current opperation"
		                Write-Host "*Return*   Return to main menu"
		                Write-Host "*Exit*     Exit the application"
			            Write-Host " "
			            $UserData = Read-Host -Prompt 'Enter Group'
						$UserData = IsDataThere -Name $UserData
						Switch ($UserData)
						{							
							'Reset'
							{
								$UserName = $UserData
								$switchValid = $false
					            $Temp = $false
					            break
							}
							'Return'
							{
								$UserName = $UserData
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
										$I = 0
										while($valid2)
										{
											if ($Usercsv.name[$I] -eq $UserData)
											{
												$I = $Usercounter
												$valid = $false
												$valid2 = $false
												$truth2 = $false
												#Write-Host "Correct"
												#pause
												Invoke-Command -ComputerName $ComputerName -ArgumentList $UserName, $UserData -Credential ($Credential) -ScriptBlock {Remove-ADGroupMember -Identity $args[1] -Members $args[0]}
											}
											else
											{
												$Usercurrent = $Usercsv.name[$I]
												#Write-Host "$UserData is not $Usercurrent"
												#pause
												$I++
												if ($I -eq $Usercounter)
		                                        {
													$switchValid = $false
													$Temp = $false													
													$valid = $false
			                                        $valid2 = $false						                            
		                                        }
											}
										}
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
									Write-Host " "	
				                }
								if(!$truth2)
								{
									cls
                                    Write-Host "Domain User $UserName is part of these groups"
		                            Write-Host " "
		                            ([ADSISEARCHER]"samaccountname=$($UserName)").Findone().Properties.memberof -replace '^CN=([^,]+).+$','$1'  
		                            Write-Host " "					
					                Write-Host "User $UserName has been removed from group $UserData"
					                Write-Host " "										
								}
								break
						    }   
						}
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
                $userData = Read-Host -Prompt 'Enter Choice'
				$userData = IsDataThere -Name $userData
				$switchvalue = CheckIfValid $userData
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