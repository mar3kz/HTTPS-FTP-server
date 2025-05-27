<h1 align="center">Generování a aplikování certifikátů</h1>
protože tato stránka neběží na WWW, proto nemůžeme požádat nějakou CA, aby nám vygenerovala certifikát, proto abychom náš server zabezpežili HTTPS, tak si můžeme vygenerovat vlastní certifikát tzv. self-assigned certificate pomosí OpenSSL, což je knihovna, jak z názvu může vypovídat právě na toto dělaná, některé certifikáty stojí peníze, ale postupem času se Let's encrypt (CA) rozhodli udělat to, že budou vydávat certifikáty zdarma za účelem zabezpečení internetu, ale podmínka je, že ten webový server musí běžet na WWW
<br>
<h2 align="center"><strong>Soubor obsahuje relativní cesty, proto je potřeba tento program pouštět ze složky FTP_SERVER</strong></h2>
<br>

<h1>Příkaz na vygenerování certifikátu</h1>
<pre>openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes</pre>
<p>tento příkaz nám vygeneruje certifikát, který bude platný na 365 dní, teoreticky by se mohl udělat certifikát, který bude neexpirovatelný, ale nejspíše nějaké OS/prohlížečů -> nepodporují certifikáty delší než 398 dní</p>
<p>pokud budeme chtít spustit server v browseru, tak možná prvních pár připojení nám selže, protože je to self-assigned certifikát a není assigned nějakým CA, což by mohlo dělat problémy, ale potom se samotná stránka načte do cache a nemělo by to dělat problémy, ale pokud bychom toto chtěli vyřešit, můžeme použít tento popis, který řekne browseru, že náš certifikát je v pořádku a nemusí nás na něj upozorňovat</p>
<p>toto platí pro Firefox, Google Chrome to má jinak</p>
<pre>
  1. otevřít Firefox
  2. vpravo tři čárky nahoře, otevřít nastavení
  3. Privacy & Security, scrollnout dolů => certifikáty
  4. View Certificates, Authorities => Import, vybrat certifikát
  5. Vybrat možnost, pokud chci jenom HTTPS (SSL over HTTP, tak jen tu možnost bez zmínění emailu), 
  pokud chci ověřovat email, tak zakliknout i tu možnost, kde je zmínka o emailu
  6. OK
</pre>
<br>
<p>Když jsem si dal ten certifikát do nastavení Firefoxu, tak na Forefoxu se možná ukáže to, že to je něvěřitelné spojení, ale to je jen protože ten certifikát je self-signed, ale jinak je to zašifrované, akorát ten webbrowser se toho bojí</p>
<p>Webbrowsery se dívájí do tzv. <strong>trust store</strong> v systému, kde jsou všechny certifikáty (nejvíce od SSL/TLS), kterým by se mělo věřit, ale abychom toto mohli podniknout, tak musíme vložit do další složky v systému náš .crt/.pem soubor a potom updatovat ten trust store, aby se tomu certifikátu mohlo věřit, musí se to kopírovat do <strong>/usr/local/share/</strong></p>
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
