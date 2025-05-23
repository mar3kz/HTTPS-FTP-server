<h1 align="center">HTTP protokol (Hypertext Transfer Protocol)</h1>
<ul>
  <li>protokol používající se na 7. vrstvě ISO/OSI (aplikační protokol)</li>
  <li>umožňuje přenos dat mezi clientem (web browserem) a webovým serverem</li>
  <li>HTTP je bezstavový (neuchovává informace mezi požadavky)</li>
  <li>existují cookies, cache, tokens</li>
  <li>HTTP má několik verzí protokolů, ale nejvíce se používá 1.1, potom jsou také populární 2.0/3.0, ale nejvíce je 1.1</li>
  <li><strong>HTTP 1.1 může poslat jenom request a potom se musí na něj odpovědět, potom se může pokračovat (head-of-line blocking) - takže pokud tomu tak není - TAK SE NĚKDE V KÓDU UDĚLALO NOVÉ PŘIPOJENÍ!!</strong></li>
  <li>HTTP 2, HTTP 3 může poslat několik requestů za sebou a to bez toho že každý potřebuje ihned po odeslání odpověď! (multiplexing)</li>
</ul>

<h1>HTTP protokol - metody</h1>
<p>metoda = to, co chce uživatel přes browser udělat</p>
<ul>
  <li>GET</li>
  <li>POST</li>
  <li>PUT</li>
  <li>DELETE</li>
  <li>HEAD</li>
  ...
</ul>
  <p>Existuje jich více, ale kromě prvních dvou/možná tří se ostatní moc nepoužívají</p>

<h2>GET</h2>
<p>GET znamená že chci od webovéhp serveru nějaká data</p>
<p><strong>pokud je to první GET request na web request, není tam určená žádná specifická cesta, jen verze HTTP, nastavení browseru apod. pokud už je to několikátý request (kde, je třeba request na soubor, u kterého je specifikovaná cesta, tak ce do GET requestu zahrne samotná cesta - MIME datové typy</strong></p>
<p>data se pošlou v URL a jsou vidět v URL</p>
<br>
<h2>POST</h2>
<p>slouží k posílání dat na server, neukazují se v URL</p>
<br>
<p><strong>každý řádek končí \r\n\r\n => Carriage return (0x0D - 13), Line Feed (0x0A - 10), Carriage Return (0x0D - 13), Line Feed (0x0A - 10)</strong></p>
<p>LF (0x0A) = \n = nový řádek</p>
<p>CR (0x0D) = \r = dá kurzor na začátek řádku</p>
<h1 align="center">WWW (World Wide Web), HTML (Hypertext Markup Language), web browser</h1>
<ul>
  <li>technologie, která umožňuje uživatelům dívat se po určitých webových serverech za účelem zjištění informací/jen z nudy/pro školu... z tzv. webových stránek pomocí web browseru, který nám zpřístupní cestu právě na tyto stránky pomocí určitého protokolu</li>
  <li>web browser musí mít nějaký způsob jak tyto stránky zobrazit ve web browseru, proto se vytvořil HTML (Hypertext Markup Language) => je to způsob, jak postavit základní webovou stránku/kostru stránku, které bude mít možnost se odkazovat na jiné webové stránky/soubory => hypertextový odkaz</li>
  <li>web browser ale také potřebuje získat nějak samotná data od samotných serverů => proto se musel vymyslet protokol, který by uspořádal data po síti do určité podoby, aby tomu web browsery rozuměly => HTTP protokol</li>
  <strong><li>WWW = "síť" webových serverů, který nabízejí určité informace v podobě webové stránce</li>
  <li>web server/server = počítač běžící určitý proces/program určený pro posílání/zpracování dat pro určitý protokol</li>
  <li>web browser = software, který nám umožňuje připojit se k webovému serveru za účelem prohlížení webové stránky/prohlížení souborů na našem počítači/disku</li>
  <li>HTTP = protokol (způsob, jak se data posílají, jak se data formátují) za účelem, aby určitá aplikaci mohla komunikovat s jinou</li></strong>
</ul>
