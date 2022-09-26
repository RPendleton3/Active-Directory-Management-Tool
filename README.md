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
