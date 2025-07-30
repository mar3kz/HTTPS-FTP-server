# argc, argv = len(sys.argv), sys.argv
# argv[0] = jmeno souboru, ktery se spusti

contents = []
with open("/home/marek/Documents/FTP_SERVER/TXT/files.txt", "r") as file:
    for line in file:
        line = line.split()
        contents.append(line)

# <link rel="stylesheet" href="formular_server.css">
# protoze tam pred tim bylo tohle v tom href (nespecifikovana slozka na to CSS), jenom ten nazev, coz znamena ZE SE POSLAL REQUEST NA TU STEJNOU SLOZKU (HTML) a ten soubor css
# COZ NEDAVA SMYSL, PROTOZE TO CSS JE V JINE SLOZCE, v kostce:
# nazev_souboru.css => odkazuje na stejnou slozku => . => /CSS/...
# nazev_souboru.css == ./nazev_souboru.css => STEJNA SLOZKA

start_html_code = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Soubory</title>
    <link rel="stylesheet" href="/CSS/formular_server.css">
    <link rel="icon" href="/IMAGES/icon.avif" type="image/avif">
    <!-- image/x-icon -->
</head>
<body>
    <div>
        <table>
            <thead>
                <th colspan="2"><h1>Dostupne soubory</h1></th>
            </thead>
            <tbody>
                <tr>
                    <th>Jmeno souboru</th>
                    <th>Uzivatel</th>
                </tr>
            </tbody>
"""
end_html_code = """
        </table>
    </div>
</body>
</html>
"""

# r+ cteni a zapisovani
with open("/home/marek/Documents/FTP_SERVER/HTML/files_html.html", "w") as file2:
    #file2.truncate(0)
    file2.write(start_html_code)
    contents_len = len(contents)

    file2.seek(0, 1) # 0 Bytes, 0 = zacatek, 1 = aktualni pozice, 2 = konec
    for index in range(0, contents_len):
            # jmeno_souboru cesta_k_souboru majitel_souboru
            blueprint_html_code = f"""\t\t\t\t<tr><td><a href="{contents[index][1]}" download="{contents[index][0]}">{contents[index][0]}</a></td><td>{contents[index][2]}</td></tr>\n"""
            file2.write(blueprint_html_code)

    file2.write(end_html_code)