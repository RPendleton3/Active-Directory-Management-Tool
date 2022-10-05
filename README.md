# Active-Directory-Management-Tool
PowerShell script development for easy management of active directory environment

9.20.2022 - Started working on v1 of this tool. 
            Setup ability to reset active directory password and disable user accounts. 
            Setup some validation so user can exit the script at any time.
            
            **Need to add ability to loop specific options instead of complete reset, like if you need to reset 5 passwords to make it easier
            **Change initial if statements to a switch statement for easy expandabaility
            **Setup initial entry of server logon info instead of leaving the credentials saved
            
9.21.2022 - Made multiple changes to v1 including switching if statements for switch statements.
            Started working on user validation using loops.
            Setup function to control menu validation.
            
            **Found issue when returning to the main menu, error in validation when picking new menu option
            **Resetup disable user option with new switch/loop layouts

9.22.2022 - Fixed many validation issues throughout the code allowing for proper repeating of options
            Now reset properly restarts the current objective
            Return properly returns you to the original menu
            Readded Disableuser and created Enableuser options with full functionality
            
            **Want to create a objective to create csv files of information like account lockout, last login etc
            **Find a way to whenever a user inputs a username that isnt found instead of a default powershell error, place a custom error, validation to the max

9.26.2022 - Setup additional option to add new domain user account.
            Found many issues with new code handling valadation from multiple user inputs at the same time. Fixed
            Found valadation issue with main menu where if you type exit it alerts you the value was incorrect. Fixed
            Spent alot of time theorizing and adjusting setups for report function. Export-CSV works well but formatting is bad.
            
            **Continue working with export csv and report creation
            **Find a way to whenever a user inputs a username that isnt found instead of a default powershell error, place a custom error, validation to the max
            **Code getting way to long and alot of repeats, work on converting sections into functions for ease of redundancy
            **Adjust new adduser option to take first letter of firstname and lastname to create username instead of retrieving username

9.27.2022 - Altered adduser option to take first letter of firstname and lastname to make username.
            Found multiple errors in validation dealing with exiting script during adduser due to improper syntax.
            Adjusted length of code but creating multiple functions to cutback on redundant code.
            
            **Continue working with export csv and report creation
            **Find a way to whenever a user inputs a username that isnt found instead of a default powershell error, place a custom error, validation to the max
            **Add options to Remove user accounts and Add users to groups, find way to view current users groups before placing into new group

9.30.2022 - Fixed small layout issues.
            Setup new menu option for changing organizational units with feedback before you change the organizational unit so that you can see where the account sits 
            and after to verify that the organizational unit has been changed.
            
            **Continue working with export csv and report creation
            **Find a way to whenever a user inputs a username that isnt found instead of a default powershell error, place a custom error, validation to the max
            **Add options to Remove user accounts and Add users to groups, find way to view current users groups before placing into new group
            **Find a way to simplify the code again to make it easier to read
            **Add a way to change specific parts of domain users accounts like changing address, department etc
            
10.2.2022 - Fixed small validation errors
            Setup new menu option, addgroup, which allows you to type in a username to get a real time list of current groups before having the ability to add to a new             group. After being added to the new group it shows the currently list of groups for the user to validate that the user is in the new group
            
            **Continue working with export csv and report creation
            **Find a way to whenever a user inputs a username that isnt found instead of a default powershell error, place a custom error, validation to the max
            **Find a way to simplify the code again to make it easier to read
            **Add a way to change specific parts of domain users accounts like changing address, department etc
            **I dont like the layout off the addgroup switch layout, want to rework it to pull list of all domain groups into an array and use nested loops to                       validate. Not only will it cut down on code it will be very versitile between systems an allow for placement into any and all domain groups
            
10.5.2022 - Was very unhappy with the way the addgroup option functioned and its limited use and flexability in my domain enviroment so completely scrapped it and                 started over. Found a way to pull a complete list of active groups from the domain, convert to .csv file and import into an array. Upon using that array               with incrememnting opperators i am now able to validate population into any valid group on the domain.

            **Continue working with export csv and report creation
            **Find a way to whenever a user inputs a username that isnt found instead of a default powershell error, place a custom error, validation to the max
            **Find a way to simplify the code again to make it easier to read
            **Add a way to change specific parts of domain users accounts like changing address, department etc
            **Add a flag in addgroup to stop the user if they try to place a user into a group they are already in
