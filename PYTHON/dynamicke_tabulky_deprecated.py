import subprocess # volani commands
import sys # pristup k command line arguments
import time

# path text => arg
# pokud se tento script spousti primo a pouziva se heredoc, tak to fungovat nebude, protoze heredoc se passuje jako stdin a ne jako argument
# takze jedine pomoci argumentu v execv
# input() != sys.stdin.read() ale == sys.stdin.readline!!!


# print(sys.argv)

# index() hleda polozku na indexu
# protoze jsou string immutable, tak se alternaci toho stringu vytvori novy => nova promenna
# path musi byt ve formatu /path/path/

# print("lines: " + str(lines))

def get_contents():
        with open("/tmp/dynamic_table.txt", "r+") as file:
                contents = file.read()
                file.seek(0)
                file.truncate(0)

                return contents.split("\n")

def fill_file(contents):
        # prvnich 10 Bytes bude v bezpeci a z toho se da zjistit ta velikost
        length_contents = len(contents)
        how_many_zeroes = len("0"*9) - len(str(length_contents))
        zeros = "0" * how_many_zeroes

        if how_many_zeroes < 0:
                print("Moc velke contents")
                sys.exit()

        final_contents = f"{length_contents}${zeros}{contents}"
        print(final_contents + "tady jsem! Christ is King" + " " + str(len(final_contents)))
        print(len(final_contents.encode("utf-8")))
        print("tady je ten length\n\n\n")
        with open("/tmp/dynamic_table.txt", "w") as file:
                file.write(final_contents)

        with open("/tmp/dynamic_table.txt", "r") as file2:
                x = file2.read()
                print("\n\n\n\n\n\n\n\n\n\nUPLNE KONEC U PYTHON SCRIPTU" + x)
lines = get_contents()
if len(lines) <= 1:
        quit()
        sys.exit()

output = ""
for line in lines:
        if "$./" in line and "<a href=" in line:
                # path/$./path
                replaced_line = line.replace("$./", "")
                output += replaced_line
        else:
                output += line
fill_file(output)

sys.exit()

# predavani multiline komentare => ''
# nastava ale problem pokud v tom textu bude slovo s '', jako treba 'tree', potom si to bude myslet ze ' patri k tomu stringu...vyhodi to error
# proto je tzv. heredoc a pouziva se: cat << 'NECO_NAPSAT'
# rtvurhvuvhv
# EOF
# a vypise se to

# python python_script.py arg1 arg2 << 'NECO'
# ...


# if len(sys.argv) < 2: # pokud heredoc < 2
#         print("Nebyly poslane vsechny argumenty!")
#         quit() # poslano jenom nazev skriptu => default
# def read_input():
#         final_input = ""
#         line_count = 0
#         while True:
#                 line = sys.stdin.readline()
#                 if "EOF" in line:
#                         break
#                 final_input += line
#                 line_count += 1

#                 if line_count == 10:
#                         break


#         sys.stdin.close()
#         print("\n\n\n\n\n\n\n\n\nHALO TADY FUNKCE")
#         print(final_input)
#         return final_input
# # stdin_input = sys.stdin.read() # pokud heredoc
# stdin_input = read_input()
# time.sleep(2)
# lines = stdin_input.split("\n")
# sys.stdin.close()

"""
<!DOCTYPE html>
<html>
<head>
 <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
 <meta name="Author" content="Made by 'tree'">
 <meta name="GENERATOR" content="tree v2.2.1 © 1996 - 2024 by Steve Baker, Thomas Moore, Francesc Rocher, Florian Sesser, Kyosuke Tokoro">
 <title>Directory Tree</title>
 <style type="text/css">
  BODY { font-family : monospace, sans-serif;  color: black;}
  P { font-family : monospace, sans-serif; color: black; margin:0px; padding: 0px;}
  A:visited { text-decoration : none; margin : 0px; padding : 0px;}
  A:link    { text-decoration : none; margin : 0px; padding : 0px;}
  A:hover   { text-decoration: underline; background-color : yellow; margin : 0px; padding : 0px;}
  A:active  { margin : 0px; padding : 0px;}
  .VERSION { font-size: small; font-family : arial, sans-serif; }
  .NORM  { color: black;  }
  .FIFO  { color: purple; }
  .CHAR  { color: yellow; }
  .DIR   { color: blue;   }
  .BLOCK { color: yellow; }
  .LINK  { color: aqua;   }
  .SOCK  { color: fuchsia;}
  .EXEC  { color: green;  }
 </style>
</head>
<body>
        <h1>Directory Tree</h1><p>
        <a href="$./">.</a><br>
        ├── <a href="$./08.06.25.txt">08.06.25.txt</a><br>
        ├── <a href="$./CERTS/">CERTS</a><br>
        │   ├── <a href="$./CERTS/server-cert.pem">server-cert.pem</a><br>
        │   ├── <a href="$./CERTS/server-key-encrypted.pem">server-key-encrypted.pem</a><br>
        │   ├── <a href="$./CERTS/server-key.pem">server-key.pem</a><br>
        │   └── <a href="$./CERTS/server-req.pem">server-req.pem</a><br>
        ├── <a href="$./CSS/">CSS</a><br>
        │   └── <a href="$./CSS/formular_server.css">formular_server.css</a><br>
        ├── <a href="$./Christ Is King/">Christ Is King</a><br>
        ├── <a href="$./HTML/">HTML</a><br>
        │   ├── <a href="$./HTML/account_taken.html">account_taken.html</a><br>
        │   ├── <a href="$./HTML/dynamicke_tabulky.html">dynamicke_tabulky.html</a><br>
        │   ├── <a href="$./HTML/files_html.html">files_html.html</a><br>
        │   ├── <a href="$./HTML/formular_prihlaseni.html">formular_prihlaseni.html</a><br>
        │   ├── <a href="$./HTML/formular_tvorba_uctu.html">formular_tvorba_uctu.html</a><br>
        │   ├── <a href="$./HTML/invalid_logins.html">invalid_logins.html</a><br>
        │   ├── <a href="$./HTML/neznamy_typ_requestu.html">neznamy_typ_requestu.html</a><br>
        │   └── <a href="$./HTML/try.html">try.html</a><br>
        ├── <a href="$./IMAGES/">IMAGES</a><br>
        │   ├── <a href="$./IMAGES/icon.avif">icon.avif</a><br>
        │   └── <a href="$./IMAGES/icon.ico">icon.ico</a><br>
        ├── <a href="$./LICENSE.md">LICENSE.md</a><br>
        ├── <a href="$./NOTES_HTTP_PROTOCOL.md">NOTES_HTTP_PROTOCOL.md</a><br>
        ├── <a href="$./NOTES_NGHTTP2_LIBEVENT_LIBRARY.md">NOTES_NGHTTP2_LIBEVENT_LIBRARY.md</a><br>
        ├── <a href="$./NOTES_NONTECHNICAL.md">NOTES_NONTECHNICAL.md</a><br>
        ├── <a href="$./NOTES_SSL_PROTOCOL.md">NOTES_SSL_PROTOCOL.md</a><br>
        ├── <a href="$./PYTHON/">PYTHON</a><br>
        │   ├── <a href="$./PYTHON/dynamic_table.py">dynamic_table.py</a><br>
        │   ├── <a href="$./PYTHON/dynamicke_tabulky.py">dynamicke_tabulky.py</a><br>
        │   ├── <a href="$./PYTHON/make_user_directories.py">make_user_directories.py</a><br>
        │   └── <a href="$./PYTHON/path_to_open_serverside.py">path_to_open_serverside.py</a><br>
        ├── <a href="$./README.md">README.md</a><br>
        ├── <a href="$./TXT/">TXT</a><br>
        │   ├── <a href="$./TXT/accounts.txt">accounts.txt</a><br>
        │   ├── <a href="$./TXT/available_commands.txt">available_commands.txt</a><br>
        │   ├── <a href="$./TXT/files.txt">files.txt</a><br>
        │   └── <a href="$./TXT/log.txt">log.txt</a><br>
        ├── <a href="$./cert-with-key.p12">cert-with-key.p12</a><br>
        ├── <a href="$./connect_try">connect_try</a><br>
        ├── <a href="$./connect_try.c">connect_try.c</a><br>
        ├── <a href="$./connect_try_server">connect_try_server</a><br>
        ├── <a href="$./connect_try_server.c">connect_try_server.c</a><br>
        ├── <a href="$./copy">copy</a><br>
        ├── <a href="$./copy - with partial nghttp2.c">copy - with partial nghttp2.c</a><br>
        ├── <a href="$./file.txt">file.txt</a><br>
        ├── <a href="$./file_len_nano.txt">file_len_nano.txt</a><br>
        ├── <a href="$./file_len_user_made.txt">file_len_user_made.txt</a><br>
        ├── <a href="$./ftp_client">ftp_client</a><br>
        ├── <a href="$./ftp_client.c">ftp_client.c</a><br>
        ├── <a href="$./ftp_server">ftp_server</a><br>
        ├── <a href="$./ftp_server.c">ftp_server.c</a><br>
        ├── <a href="$./libevent_try_client">libevent_try_client</a><br>
        ├── <a href="$./libevent_try_client.c">libevent_try_client.c</a><br>
        ├── <a href="$./libevent_try_server">libevent_try_server</a><br>
        ├── <a href="$./libevent_try_server.c">libevent_try_server.c</a><br>
        ├── <a href="$./log.txt">log.txt</a><br>
        ├── <a href="$./logs.txt">logs.txt</a><br>
        ├── <a href="$./mq_test">mq_test</a><br>
        ├── <a href="$./mq_test.c">mq_test.c</a><br>
        ├── <a href="$./os">os</a><br>
        ├── <a href="$./subprocess">subprocess</a><br>
        ├── <a href="$./sys">sys</a><br>
        ├── <a href="$./text_paste.txt">text_paste.txt</a><br>
        ├── <a href="$./try">try</a><br>
        ├── <a href="$./try.c">try.c</a><br>
        ├── <a href="$./try2">try2</a><br>
        ├── <a href="$./try2.c">try2.c</a><br>
        ├── <a href="$./try3">try3</a><br>
        ├── <a href="$./try3.c">try3.c</a><br>
        ├── <a href="$./unlink_mqs">unlink_mqs</a><br>
        └── <a href="$./unlink_mqs.c">unlink_mqs.c</a><br>
<br><br><p>

8 directories, 64 files

</p>
        <hr>
        <p class="VERSION">
                 tree v2.2.1 © 1996 - 2024 by Steve Baker and Thomas Moore <br>
                 HTML output hacked and copyleft © 1998 by Francesc Rocher <br>
                 JSON output hacked and copyleft © 2014 by Florian Sesser <br>
                 Charsets / OS/2 support © 2001 by Kyosuke Tokoro
        </p>
</body>
</html>
"""



# <!DOCTYPE html>
# <html>
# <head>
#  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
#  <meta name="Author" content="Made by 'tree'">
#  <meta name="GENERATOR" content="tree v2.2.1 © 1996 - 2024 by Steve Baker, Thomas Moore, Francesc Rocher, Florian Sesser, Kyosuke Tokoro">
#  <title>Directory Tree</title>
#  <style type="text/css">
#   BODY { font-family : monospace, sans-serif;  color: black;}
#   P { font-family : monospace, sans-serif; color: black; margin:0px; padding: 0px;}
#   A:visited { text-decoration : none; margin : 0px; padding : 0px;}
#   A:link    { text-decoration : none; margin : 0px; padding : 0px;}
#   A:hover   { text-decoration: underline; background-color : yellow; margin : 0px; padding : 0px;}
#   A:active  { margin : 0px; padding : 0px;}
#   .VERSION { font-size: small; font-family : arial, sans-serif; }
#   .NORM  { color: black;  }
#   .FIFO  { color: purple; }
#   .CHAR  { color: yellow; }
#   .DIR   { color: blue;   }
#   .BLOCK { color: yellow; }
#   .LINK  { color: aqua;   }
#   .SOCK  { color: fuchsia;}
#   .EXEC  { color: green;  }
#  </style>
# </head>
# <body>
#         <h1>Directory Tree</h1><p>
#         [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;12288]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./">.</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./08.06.25.txt">08.06.25.txt</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4096]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./CERTS/">CERTS</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2025]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./CERTS/server-cert.pem">server-cert.pem</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3422]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./CERTS/server-key-encrypted.pem">server-key-encrypted.pem</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3272]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./CERTS/server-key.pem">server-key.pem</a><br>
#         │   └── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1724]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./CERTS/server-req.pem">server-req.pem</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./CSS/">CSS</a><br>
#         │   └── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;226]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./CSS/formular_server.css">formular_server.css</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./Christ Is King/">Christ Is King</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4096]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./HTML/">HTML</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;475]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./HTML/account_taken.html">account_taken.html</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7578]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./HTML/dynamicke_tabulky.html">dynamicke_tabulky.html</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;998]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./HTML/files_html.html">files_html.html</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2739]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./HTML/formular_prihlaseni.html">formular_prihlaseni.html</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2349]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./HTML/formular_tvorba_uctu.html">formular_tvorba_uctu.html</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;459]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./HTML/invalid_logins.html">invalid_logins.html</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;355]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./HTML/neznamy_typ_requestu.html">neznamy_typ_requestu.html</a><br>
#         │   └── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7693]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./HTML/try.html">try.html</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./IMAGES/">IMAGES</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6793]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./IMAGES/icon.avif">icon.avif</a><br>
#         │   └── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4286]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./IMAGES/icon.ico">icon.ico</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1050]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./LICENSE.md">LICENSE.md</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;8442]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./NOTES_HTTP_PROTOCOL.md">NOTES_HTTP_PROTOCOL.md</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2207]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./NOTES_NGHTTP2_LIBEVENT_LIBRARY.md">NOTES_NGHTTP2_LIBEVENT_LIBRARY.md</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;943]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./NOTES_NONTECHNICAL.md">NOTES_NONTECHNICAL.md</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;11632]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./NOTES_SSL_PROTOCOL.md">NOTES_SSL_PROTOCOL.md</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4096]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./PYTHON/">PYTHON</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2032]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./PYTHON/dynamic_table.py">dynamic_table.py</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7416]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./PYTHON/dynamicke_tabulky.py">dynamicke_tabulky.py</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1127]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./PYTHON/make_user_directories.py">make_user_directories.py</a><br>
#         │   └── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./PYTHON/path_to_open_serverside.py">path_to_open_serverside.py</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;9198]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./README.md">README.md</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4096]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./TXT/">TXT</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;180]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./TXT/accounts.txt">accounts.txt</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;169]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./TXT/available_commands.txt">available_commands.txt</a><br>
#         │   ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;402]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./TXT/files.txt">files.txt</a><br>
#         │   └── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;12805]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./TXT/log.txt">log.txt</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2723]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./cert-with-key.p12">cert-with-key.p12</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;20768]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./connect_try">connect_try</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2209]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./connect_try.c">connect_try.c</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;20560]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./connect_try_server">connect_try_server</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1900]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./connect_try_server.c">connect_try_server.c</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;41832]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./copy">copy</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;83888]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./copy - with partial nghttp2.c">copy - with partial nghttp2.c</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;106]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./file.txt">file.txt</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./file_len_nano.txt">file_len_nano.txt</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./file_len_user_made.txt">file_len_user_made.txt</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;87760]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./ftp_client">ftp_client</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;136031]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./ftp_client.c">ftp_client.c</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;115208]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./ftp_server">ftp_server</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;165737]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./ftp_server.c">ftp_server.c</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;24216]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./libevent_try_client">libevent_try_client</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4092]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./libevent_try_client.c">libevent_try_client.c</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;24704]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./libevent_try_server">libevent_try_server</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4129]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./libevent_try_server.c">libevent_try_server.c</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./log.txt">log.txt</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./logs.txt">logs.txt</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;1781448]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./mq_test">mq_test</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;915]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./mq_test.c">mq_test.c</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;4295633]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./os">os</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;4434146]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./subprocess">subprocess</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;11717106]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./sys">sys</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;27963]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./text_paste.txt">text_paste.txt</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;19336]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./try">try</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2074]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./try.c">try.c</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;18504]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./try2">try2</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7318]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./try2.c">try2.c</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;1781504]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./try3">try3</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;513]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./try3.c">try3.c</a><br>
#         ├── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;18848]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./unlink_mqs">unlink_mqs</a><br>
#         └── [&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1358]&nbsp;&nbsp;&nbsp;&nbsp;<a href="/home/marek/Desktop/$./unlink_mqs.c">unlink_mqs.c</a><br>
# <br><br><p>

# 8 directories, 64 files

# </p>
#         <hr>
#         <p class="VERSION">
#                  tree v2.2.1 © 1996 - 2024 by Steve Baker and Thomas Moore <br>
#                  HTML output hacked and copyleft © 1998 by Francesc Rocher <br>
#                  JSON output hacked and copyleft © 2014 by Florian Sesser <br>
#                  Charsets / OS/2 support © 2001 by Kyosuke Tokoro
#         </p>
# </body>
# </html>



# nebo bych mohl udelat \' ale na to by bylo prohledavani zase kazdeho radku
# a kdyz jsem delal cteni ze stdin tak to taky nejak nefungovalo, nesel myslim nejak zavrit stdin
# ale mozna chunked reading by fungovalo

# # jedine co funguje je tohle a funguje to protoze v C v snprintf se neda udelat opravdovy novy radek jen \n, coz vezme shell jako znak, proto to spolehlive funguje jenom v interaktivnim shellu, taky pokud by shell chtel zmenit nejake promenne v uvozovkach, tak jedine v "", ale to by zase neslo v C v snprintf, protoze to by si myslelo, ze je ukonceny string, ale i pres to vsechno se to nejak do toho stdin da dat ale nezaregistruje se EEOF na konci heredoc, moz se by slo udelat cteni po chunkach...
# zsh -c 'python3 PYTHON/dynamicke_tabulky.py arg' << EOF
# >quote NOVY OPRAVDOVY RADEK A TADY POTREBUJU PASTENOUT TEN TREE -H $ (tim ze udelam ctrl v - musi to byt na novem radku - jinak to nefunguje!!)
# obsaah
# obsah
# obsah to EOF muze byt i tady
# EOF'

# ALE JE DULEZITE ZE U TOHO PRVNIHO JE OPRAVDOVY RADEK A NE JEN \n
# a nekdy to hazelo command list too long
# takze skoro nemozne, proto je lepsi nejaky file