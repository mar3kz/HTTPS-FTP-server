<h1 align="center">Generování a aplikování certifikátů</h1>
protože tato stránka neběží na WWW, proto nemůžeme požádat nějakou CA, aby nám podepsala náš certifikát jejich intermediate certifikátem, který je také podepsán nějakým root certifikátem (SSL certifikát chain = intermediate CAs na větší security), za účelem abychom náš server zabezpežili HTTPS, tak si musíme vygenerovat vlastní certifikát tzv. self-assigned certificate pomocí OpenSSL (nebo pomocí čehokoliv jiného), což je knihovna, jak z názvu může vypovídat právě na toto dělaná
<br><br>
Abychom neměli pořád ikonku toho nezabezpečeného zámečku, tak si musíme vygenerovat svůj vlastní certifikát a private key, který budeme považovat za lokálního root CA, potom si vygenerujeme privátní klíč a CSR (Certificate Signing Request), kde si vyplníme informace o tom našem requestu (podobné jako samotný certifikát) a potom jen necháme podepsat našim lokalním root CA a do Firefoxu dáme ten lokální root CA a v kódu budeme používat ten server certifikát a ten klíč
<br><br>
Některé certifikáty stojí peníze, ale postupem času se Let's encrypt (CA) rozhodli udělat to, že budou vydávat certifikáty zdarma za účelem zabezpečení internetu, ale podmínka je, že ten webový server musí běžet na WWW (vylepšení placeného certifikátu = 27/7 podpora, záruka...)
<br><br>
<h2 align="center"><strong>Soubor obsahuje relativní cesty, proto je potřeba tento program pouštět ze složky FTP_SERVER</strong></h2>
<br>

<h1>Příkaz na vygenerování certifikátu</h1>
<pre>openssl req -x509 -newkey rsa:4096 =dazs 365 -keyout CA-key.pem -out CA-cert.pem</pre>
<p>tento příkaz nám vygeneruje certifikát, který bude platný na 365 dní, teoreticky by se mohl udělat certifikát, který bude neexpirovatelný, ale nejspíše nějaké OS/prohlížečů -> nepodporují certifikáty delší než 398 dní</p>
<br>
<p>Tento certifikát budeme považovat jako lokální root CA, použijeme ho k podepisování CSR, ten samotný klíč bude zašifrovaný, takže se každý k němu nedokáže dostat, pokud by někdo získal ten soubor, tak stejně musí vědět to heslo na ten soubor, aby se opravdu dostal k samotnému klíči</p>

<p>OpenSSL se zeptá na různé informace o tom certifikátu, CN může být cokoliv, webbrowsery to už moc nepoužívají</p>

<pre>openssl req -newkey rsa:4096 -keyout server-key.pem -out server-req.pem</pre>
<p>Toto je příkaz na vygenerování našeho server privátního klíče a signing requestu, kde se bude nás ptát na úplně samé otázky jako u přechozího příkazum bude potřeba zase nějaké heslo k zabezpečení samotného souboru</p>
<pre>touch server-ext.cnf</pre>
<pre>echo "subjectAltName=DNS:*.web.internal,IP:127.0:0.1" >> server-ext.cnf</pre>
<p>vyrobení SAN, subjectAltName jsou všechny názvy, pod kterými ten web můžeme najít, když to napíšeme do URL</p>
ta * znamená, že to platí pro všechny subdomény první úrovně => neco.web.internal, xd.web.internal, ale nebude to fungovat na domény druhého stupně => neco.neco.web.internal toto už nepůjde
<pre>openssl x509 -req -in server-req.pem -days 365 -CA CA-cert.pem -CAkey CA-key.pem -CAcreateserial -out server-cert.pem -extfile server-ext.cnf</pre>
po zadání hesla, vygenerování našeho leaf certifikátu
<br>
ale po spuštění se bude pořád chtít heslo ke klíči a to může být docela časově náročné (chce to heslo na decrypci), to může být časově náročné, proto si to přejmenuji a "zkopíruji" a potom dalším příkazem odstraním encrypci samotného klíče
<br><br>
<pre>mv ./CERTS/server-key.pem ./CERTS/server-key-encrypted.pem</pre>
<pre>openssl rsa -in server-key-encrypted.pem -out server-key.pem</pre>
<br>
<h2>Pokud si certifikát nepodepíšeme lokálním root CA</h2>
<p>pokud budeme chtít spustit server v browseru, tak možná prvních pár připojení nám selže, protože je to self-assigned certifikát a není assigned nějakým CA, což by mohlo dělat problémy, ale potom se samotná stránka načte do cache a nemělo by to dělat problémy, ale pokud bychom toto chtěli vyřešit, můžeme použít tento popis, který řekne browseru, že náš certifikát je v pořádku a nemusí nás na něj upozorňovat</p>
<p>toto platí pro Firefox, Google Chrome to má jinak</p>

<h2>Musíme si naimportovat lokální root CA do webbrowseru, potom se ten certifikát zkontroluje, že je podepsán trusted root CA, protože jsem ten certifikát tam importovali</h2>
<pre>
  1. otevřít Firefox
  2. vpravo tři čárky nahoře, otevřít nastavení
  3. Privacy & Security, scrollnout dolů => certifikáty
  4. View Certificates, Authorities => Import, vybrat <strong>lokální root CA</strong> certifikát / nebo pokud nemáme podepsané nahrát jen samotný leaf certifikát
  5. Vybrat možnost, pokud chci jenom HTTPS (SSL over HTTP, tak jen tu možnost bez zmínění emailu), 
  pokud chci ověřovat email, tak zakliknout i tu možnost, kde je zmínka o emailu
  6. OK
</pre>
<br>
<p>Když jsem si dal ten certifikát do nastavení Firefoxu, tak na Forefoxu se možná ukáže to, že to je něvěřitelné spojení, ale to je jen protože ten certifikát je self-signed, ale jinak je to zašifrované, akorát ten webbrowser se toho bojí</p>
<p>Webbrowsery se dívájí do tzv. <strong>trust store</strong> v systému, kde jsou všechny certifikáty (nejvíce od SSL/TLS), kterým by se mělo věřit, ale abychom toto mohli podniknout, tak musíme vložit do další složky v systému náš <strong>.pem</strong> soubor a potom updatovat ten trust store, aby se tomu certifikátu mohlo věřit, musí se to kopírovat do <strong>/usr/local/share/ca-certificates</strong></p>
<pre>sudo cp [path_source_cert_file_cert] /usr/local/share/ca-certificates</pre>
<pre>sudo mv /usr/local/share/ca-certificates/cert.pem /usr/local/share/ca-certificates/cert.crt</pre>
<pre>sudo update-ca-certificates</pre>
<strong>Do ca-certificates se dávají jenom lokální root CAs</strong>
<p>mv = move/rename</p>
<hr>
<h1 align="center">Jak použít OpenSSL, aby z HTTP => HTTPS</h1>
<p>k dohledání potřebným informací jsou nejlepší tyto stránky</p>
<ul>
  <li>https://openssl-library.org/</li>
  <li>https://github.com/openssl/openssl</li>
  <li>https://wiki.openssl.org/index.php/Main_Page</li>
  <li>https://github.com/openssl/openssl/wiki/Simple_TLS_Server</li>
  <li>https://wiki.openssl.org/index.php/SSL/TLS_Client</li>
</ul>
<br>
<p>doporučuji si každou funkci vyhledat pomocí příkazu 
<pre>
  grep
</pre>
v shellu, abych se mohl podívat, v jakém header file se nachází a potom se mohu podívat na oficiální, jestli je tam není popis/jestli není zastaralá (deprecated)</p>
<br>
<h2>Jak na to, aby se z kódu stalo HTTPS z HTTP je potřeba</h2>
<pre>
  1. inicializace knihovny OpenSSL
  2. vybrání metody (SSL/TLS - SSL se už skoro vůbec nepoužívá)
  3. vytvoření SSL_CTX struktury obsahující nastavení pro SSL/TLS komunikaci - šablona
  4. přiřazení metody do struktury
  5. (nastavení jestli server bude nějak ověřovat klienta) - povinný, pokud chci ověřovat clienta jeho certifikátem, jinak nepovinný
  6. (přidání dalších nastavení/specifikací pro strukturu SSL_CTX) - nepovinný
  7. načtení certifikátu do SSL_CTX
  8. načtení private key do SSL_CTX
  9. vytvořit konkrétní instanci připojení struktury SSL
 10. čekání na clienta na zahájení SSL/TLS handshake
 11. acceptnout SSL/TLS komunikace
 12. SSL_write()/SSL_read()
 13. SSL_shutdown(SSL)
 14. free(SSL_CTX, SSL)
</pre>
<br><br><br>
<ul>
  <li>lokální root CA = certifikát jako každý jiný, který budeme považovat za root CA a kterému dáme náš CSR (Certificate Signing Request)</li>
  <li>CSR (Certificate Signing Request) = elektronický "dokument", kde jsou určité informace o identifikaci lokace, autority, názvu webu za účelem předání tohoto dokumentu jakékoliv root CA k podepsání, až dojde podepsání, tak nám root CA vygeneruje náš server certifikát</li>
  <li>CN (Common Name) = je hlavní jméno samotného webu, dříve se to používalo jako jediné ověřování toho, že klient opravdu mluví se samotným webem, ale teď se už skoro vůbec nepoužívá a webbrowsery už na to nedávají důraz, teď se používá SAN</li>
  <li>SAN (Subject Alternative Name) = je prakticky extenze CN (Common Name), používá se více názvů, pod kterýn web může být vyhledán, ověření spočívá v tom, že webbrowser se kouká na jeho list SAN dokud nenarazí na jméno napsané do URL, pokud najde => connection secure, pokud nenajde => connection unsecure</li>
  <li>PKCS#12 = typ souboru podobný .zip, kde je samotný certifikát a key, slouží k tomu, aby se informace/soubory neztratily</li>
  <li>Některé firmy mohou být jak root CAs, tak i intermediate CAs, ale intermediate CAs a chain certificates, nejsou zase tak potřeba k pouhému implementování SSL/TLS certifikátu (Let's Encrypt)</li>
</ul>
<br>
https://www.youtube.com/watch?v=7YgaZIFn7mY&list=LL&index=2
