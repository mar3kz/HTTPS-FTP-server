<h1 align="center">Generování a aplikování certifikátů</h1>
protože tato stránka neběží na WWW, proto nemůžeme požádat nějakou CA, aby nám vygenerovala certifikát, proto abychom náš server zabezpežili HTTPS, tak si můžeme vygenerovat vlastní certifikát tzv. self-assigned certificate pomosí OpenSSL, což je knihovna, jak z názvu může vypovídat právě na toto dělaná, některé certifikáty stojí peníze, ale postupem času se Let's encrypt (CA) rozhodli udělat to, že budou vydávat certifikáty zdarma za účelem zabezpečení internetu, ale podmínka je, že ten webový server musí běžet na WWW
<br><br>
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
