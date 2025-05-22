<h1 align="center">SSL/TLS</h1>
<ul>
  <li><p>SSL = Secure Sockets Layer (předchůdce TLS)</p></li>
  <li><p>TLS = Transport Layer Security</p></li>
  <li><p><strong>Jsou to protokoly, které používají různé šifrovací postupy za účelem bezpečné konverzace přes sockety</strong></p></li>
  <li><p>Nejvíce se používají u HTTPS (HTTP over SSL/TLS), IoT, cloud, hry => všude, kde je potřeba bezpečné konverzace přes síť</p></li>
  <li><p>Říká se SSL/TLS, jen protože je to z historických důvodů, jinak tento protokol se jmenuje TLS (Transport Layer Security)</p></li>
</ul>

  
<br>
<p><strong>Protokol = Způsob/pravidla jak se data posílají přes socket, nic více! Jen údáva strukturu, taky i strukturu, jak i data vypadají FTP, HTTP, HTTP...</strong></p>
<p>Implementace SSL/TLS je velice těžká, dokonce i pro více zkušené, stačí pokazit jednu šifru, poslat špatně nějaká data při handshaku a s bezpečností se můžeme rozloučit</p>
<h2 align="center">Verze SSL a TLS</h2>
<div align="center">
  <table>
      <thead>
          <tr>
              <th>Verze</th>
              <th>Rok vydání</th>
              <th>Status</th>
              <th>Doporučení</th>
          </tr>
      </thead>
      <tbody>
          <tr class="bad">
              <td><strong>SSL 2.0</strong></td>
              <td>1995</td>
              <td>Zakázáno</td>
              <td>❌</td>
        </tr>
          <tr class="bad">
              <td><strong>SSL 3.0</strong></td>
              <td>1996</td>
              <td>Zakázáno</td>
              <td>❌</td>
          </tr>
          <tr class="bad">
              <td><strong>TLS 1.0</strong></td>
              <td>1999</td>
              <td>Zakázáno</td>
              <td>❌</td>
          </tr>
          <tr class="warning">
              <td><strong>TLS 1.1</strong></td>
              <td>2006</td>
              <td>Zakázáno</td>
              <td>❌</td>
          </tr>
          <tr class="good">
              <td><strong>TLS 1.2</strong></td>
              <td>2008</td>
              <td>Bezpečné</td>
              <td>✅</td>
          </tr>
          <tr class="good">
              <td><strong>TLS 1.3</strong></td>
              <td>2018</td>
              <td>Nejbezpečnější</td>
              <td>✅</td>
          </tr>
      </tbody>
  </table>
</div>

<h1 align="center">Funkce TLS 1.2</h1>
<p>V RFC je popsán TLS 1.2, tak že nejdříve se mluví o tom, jaké datové typy mají být použity pro různé kryptografikcé operace a potom se dostává do části, kde popisuje samotný běh tohoto protokolu</p>
<p><strong>TLS má tři subprotokoly</strong></p>
<ul>
  <li>The Handshake Protocol</li>
  <li>Change Cipher Spec Protocol</li>
  <li>Alert Protocol</li>
</ul>

<br>
<h2>The Handshake Protocol</h2>
<ul>
  <li><p>Úplně první protokol (subprotokol), musí se udělat/uskutečnit ještě před tím, než se začnou posílat jakákoliv data přes sockety</p></li>
  <li><p>Slouží k specifikování samotných verzí šifrovacích itmů, jaké verze těchto itmů, session ID, certifikát od CA, master secret (i také premaster secret), is resumable (jestli se dá session znovu spustit), kompresních algoritmů</p></li>
  <li><p>Skládá se z více zpráv</p></li>
</ul>

<h2>Change Cipher Protocol</h2>
<ul>
  <li><p>Jedna zpráva, která specifikuje změnu použitých šifer</p></li>
</ul>
<h2>Alert Protocol</h2>
<ul>
  <li><p>Slouží k identifikaci problému, obsahuje zprávu, co se stalo (špatně)</p></li>
  <li><p>Nejdůležitější protokol je The Handshake Protokol</p></li>
</ul>
<br>

<h3>Jaký je rozdíl mezi symetrickými šiframi a asymetrickými šiframi?</h3>
<ul>
  <li><p>symetrické šifry používají pouze jedek klíč k encryption & decryption</p></li>
  <li><p>asymetrické šifry používají jiný klíč k encryption a decryption</p></li>
</ul>

<br><br>

<h1>The Handshake Protocol</h1>
<ul>
  <li>Aplikace by neměla přistoupit k posílání přes sockety/porty, které nejsou tak secure i když vyžadují secure sockety/porty</li>
  <li>Cíl tohoto protokolu by mělo být si exchangnout hello zprávy za účelem na dohodnutí se na algoritmech, posílání random values...</li>
  <li>Exchangenutí parametrů kryptografických parametrů na dohodnutí se vygenerování premaster secret a master secret</li>
</ul>
<br>

<p>  
Tyto cíle se dokážou pomocí tzv. handshaku (posílání informací za účelem navázání spojení mezi dvěma stranami), tento handshake se skládá ze čtyř zkrácených zpráv/protokolů: ClientHello, ServerHello, posílání certifikátu, ověření certifikátu a generování session keys
</p>

<br>

<h2>Slovní popis komunikace SSL/TLS</h2>

<p>
Tato komunikace se skládá nejdříve z pozdravení obou stran, kde jedna strana může vyžadovat certifikáty a nebo další požadavky, toto je dobrovelné, následně následuje generování klíčů a posílání potřebných dat, ze kterých klient získá klíče na hashovací funkce, klient pošle zprávu serveru ať přepne na encryptovanou komunikaci, potom pošle, že je připraven na tuto komunikaci, server potvrdí a také pošle, že je připraven na komunikaci pomocí encryptování, toto je konec handshaku, potom následují encryptovaná data a na konci každá strana pošle informaci o tom, že by chtěla zavřít spojení.
</p>

<h2>Vizuální ukázka komunikace</h2>
<pre>
  CLIENT                  SERVER
  ClientRandom
  ClientHello ---->
                    ServerRandom
               <---- ServerHello
             Generate pre-master
            Generate private key
          Generate master secret
                Session keys m.s
                <---- ServerCert
          <---- Server HelloDone
   Generate pre-master
   Generate master secret
   Session keys m.s.
   Authentication of cert
   I want encryption ---->
          <---- Encryption it is
         Encryption data
  I don't want to talk ---->
                 <----Me neither
           Session end
</pre>


<br>
<ol>
  <li>client hello</li>
  <li>server hello</li>
  <li>(certifikát = server -> client)</li>
  <li>(certifikát request = server -> client)</li>
  <li>(parameters, public key exchange for DH - only DH!)</li>
  <li>server hello done</li>
  <li>(certifikát = client -> server)</li>
  <li>(verification that client actually owns the certificate)</li>
  <li>client wants encryption communication</li>
  <li>client is ready</li>
  <li>server is ready, encryption begins now</li>
  <li>communication</li>
  <li>close notification</li>
</ol>
<br>
<p>Taky existuje i TLS i asymetrickými šiframi - Diffie-Hellman key exchange</p>

<h1>Komunikace SSL/TLS</h1>

<h3>ClientHello</h3>
<p>Obsahuje</p>
<ul>
  <li>Protocol version</li>
  <li>Client Random - 32 Bytes (256 bits)</li>
  <li>(Session ID - z předchozí relace)</li>
  <li>Cipher suites</li>
  <li>List of compression methods</li>
  <li>(kdyžtak nějaké extensions)</li>
</ul>
<br>

<h3>ServerHello</h3>
<p>Obsahuje</p>
<ul>
  <li>Selected protocol version</li>
  <li>Server Random - 32 Bytes (256 bits)</li>
  <li>Session ID - nově vygenerované</li>
  <li>Selected cipher suites</li>
  <li>List of selected compression methods</li>
  <li>(kdyžtak nějaké extensions)</li>
</ul>
<br>

<p>Server si generuje <strong>svůj vlastní privátní klíč</strong> - nejčastější volba RSA (asymetrická šifra - private key na decrypting a public na encrypting)</p>

<br>
<h3>Server posílá certifikát</h3>
<p>Obsahuje</p>
<ul>
  <li>certifikát obsahující kromě několika informací také i <strong>public key serveru</strong></li>
  <li>public key</li>
</ul>

<p>
(ServerKeyExchange - pokud je použit DF-H, server pošle parametry DH/ECDHE, u RSA tomu tak není)
(CertificateRequest - pokud server chce certifikát od clienta)
</p>

<h3>ServerHelloDone</h3>
<p>Obsahuje</p>
<ul>
  <li>zprávu o ukončení handshake ze strany serveru</li>
</ul>

<h3>ClientKeyExchange</h3>
<p>Obsahuje</p>
<ul>
  <li>vypočítaný premaster secret - zašifruje public klíčem, server si ho dešifruje jeho privátním klíčem - asymetrické</li>
</ul>

<p>Oba si spočítají Master Secret, sloužící k vytvoření klíčů (session keys - server/client na šifrování samotných dat, které se pošlou po socketu, MAC keys apod.)</p>

<h3>ChangeCipherSpec</h3>
<p>Obsahuje</p>
<ul>
  <li>zprávu o tom, že od teď bude probíhat komunikace se šifrováním</li>
</ul>

<h2>Důležitá informace</h2>
<p>Samozřejmě, že každá SSL/TLS komunikace se může lišit, protože nikde nejsou přesně stanovené pravidla na komunikaci, toto znamená, že certifikát od serveru se vůbec nemusí poslat za určitých okolností, komunikace může zahrnovat ještě nějaké další informace o extsension komunikace SSL/TLS, tento popis je pouze informační.</p>

<h2>Appendix</h2>
<ul>
  <li>CA (Certificate Authority) = je důvěryhodná organizace, která vydává certifikáty (některé jsou více trusted, některé méně - méně trusted organizace)</li>
  <li>certifikát = "digitální průkaz" na internetu, který ověřuje že webový server patří opravdu webu a ne jen nějakému člověku</li>
  <li>MAC (Message Authentication Code) = je způsob ověření, že zpráva od klienta/serveru je autentická, je to hash klíče a zprávy , které se přidá do jiné hashovací funkce</li>
  <li>HMAC = konkrétní verze MAC - šifra</li>
  <li>pre master secret = část dat, ze které se udělá master secret, vytvoří se tak že se skombinuje session key a náhodných 32 Bytes => 48 Bytes</li>
  <li>master secret = část dat, ze kterých se potom odvodí privátní klíče, HMAC (algoritmus pro MAC)..., vytvoří se z client random a server random a pre master secret => 48 Bytes</li>
  <li>clienet random/server random = náhodné 32 Bytes pro PMS (pre master secret, master secret)</li>
  <li>kontext v kryptografii = soubor paramterů pro správné fungování protokolu/operace</li>
  <li>cipher suites = sada kryptografických algoritmů</li>
  <li>session keys = klíče sloužící k šifrování dat určených pro poslání přes socket, server a client používají tyto klíče pro dešifraci obsahu poslaného přes sockety, server a client mají stejné session keys</li>
</ul>

<br>
<p>Pro certifikáty se používá x509</p>
<br><br>
<p>https://tls12.xargs.org/#open-all</p>
<p>https://www.cloudflare.com/learning/ssl/what-happens-in-a-tls-handshake/</p>
<p>https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.9</p>
<p>https://www.ibm.com/docs/en/cloud-paks/z-modernization-stack/2023.4?topic=handshake-tls-12-protocol</p>
<p>https://cabulous.medium.com/tls-1-2-andtls-1-3-handshake-walkthrough-4cfd0a798164</p>
<p>https://www.ssl.com/article/ssl-tls-handshake-ensuring-secure-online-interactions/</p>

