import sys
import time
import os
# tree $ /path/
#         └── <a href="$/media/sf_projects_on_vm/FTP_SERVER/unlink_mqs.c">unlink_mqs.c</a><br>

# tree $/path/
#         └── <a href="$/media/sf_projects_on_vm/FTP_SERVER/./unlink_mqs.c">unlink_mqs.c</a><br>

# tree /path/
#         └── <a href="/media/sf_projects_on_vm/FTP_SERVER/./unlink_mqs.c">unlink_mqs.c</a><br>


# tento file je pro verzi tree $ /path/

# protoze pro tree -H $ /path/ se dava /path/, ktera konci s /, tak jedna cast te tabulky je s dvema //, coz potom dela problem pri requestech a musi se to pozmenit, protoze //.txt ani /.txt nefunguje, tak muzu mit normalni podminku
def get_contents():
        with open("/tmp/dynamic_table.txt", "r") as file:
                output = ""
                lines = file.read().split("\n")
                print(str(lines) + "\n")


                # pokud radek ma //, udela to na / => vetsinou pri indikovani, jaka slozka to je, pokud je v radce $, zmeni to na text PATH_REQUEST, kde potom ftp_server.c s tim pracuje dal
                for line in lines:
                        line_to_check = ""
                        if "//" in line:
                                replaced_line = line.replace("//", "/")
                                line_to_check = replaced_line

                        if not line_to_check: # znamena ze je variable prazdna a konvence, ze to je string
                                line_to_check = line

                        print(f"line to check '{line_to_check}'")
                        if "$" in line_to_check:
                                print("LINE: " + line_to_check + """  "  """)
                                last_quation_marks_index = line_to_check.rfind("""\"""") # find() zleva doprava, rfind() zprava doleva
                                print(last_quation_marks_index)
                                if line_to_check[last_quation_marks_index - 1] == "/": # pokud je to slozka
                                     replaced_line = line_to_check.replace("$", "PATH_REQUEST")
                                     output += replaced_line   
                                else:
                                        replaced_line = line_to_check.replace("$", "")
                                        output += replaced_line
                        else:
                                output += line_to_check
                print(output)
                return output

def write_contents():
        with open("/tmp/dynamic_table.txt", "r+") as file:
                contents = get_contents()

                file.seek(0)
                file.truncate(0)

                length_contents = len(contents.encode('utf-8'))
                str_length_contents = len(str(length_contents))

                how_many_zeroes = 9 - str_length_contents
                zeroes = "0" * how_many_zeroes # muze byt i ""

                if how_many_zeroes < 0:
                        print("Moc velke contents!")
                        quit()  
                
                # Unicode = soubor vsech znaku na svete s nejakym cislem korespondujici s timto znakem
                # Utf-8 = zpusob ukladani textu do memory, nejake znaky maji vice Bytes nez ostatni

                # Python funguje na bazi Unicode, C na bazi Utf-8
                final_contents = f"{length_contents}${zeroes}{contents}"
                # x = final_contents.encode('utf-8')
                # print("\n\n\n\n\nfinal_contents: " + final_contents + "\n\n\n" + "len x :" + str(len(x)) + "\n\n\n")
                file.write(final_contents)

# print("\n\n\nZACATEK PYTHON SCRIPTU =============================")
write_contents()
# os.system("cat /tmp/dynamic_table.txt")
# print("\n\n\nKONEC PYTHON SCRIPTU =============================")
quit()