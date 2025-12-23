import os # pro otevirani directories
import sys # pro sys.exit()

file = open("./TXT/accounts.txt", "r") # otevirani file
to_save_path = "/tmp/ftp_server/"

os.makedirs("/tmp/ftp_server", mode=0o777, exist_ok=True)
os.makedirs("/tmp/ftp_downloaded", mode=0o777, exist_ok=True)

username_password_list = [] # pro current radek username a password
for line in file: # iterace pres radky file
    username_password_list = line.split(" ") # rozdelit radek do listu podle separatoru " " - space

    temp_path = to_save_path + username_password_list[0]

    try:
        # je to jedno jestli se pouzije funkce na rekurzivni vytvareni slozek (os.makedirs())
        os.makedirs(temp_path, mode=0o777, exist_ok=True) # 0o jako octal, diky exist_ok=True to nebude rikat, ze uz to existuje
    except Exception as error: # Exception je trida, error je instance tridy Exception => toto znamena pokud nastane nejaka chyba, tak chci ulozit informace o te chybe do promenne error typu Exception (instance tridy)
        print(f"nastala nejaka chyba: {error}")
        sys.exit(1) # 1 error, 0 successful

    username_password_list.clear()