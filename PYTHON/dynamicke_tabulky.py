import subprocess # volani commands
import sys # pristup k command line arguments

if len(sys.argv) == 1:
    print("Nebyla poslana path!")
    quit() # poslano jenom nazev skriptu => default

command = f"tree -us {sys.argv[1]}" # u = vlastnik, s = size
command_output = subprocess.getoutput(command)
command_output_list = command_output.split()


print(command_output.split())
print(command + "\n\n\n\n" + command_output)