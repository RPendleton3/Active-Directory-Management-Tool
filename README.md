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
