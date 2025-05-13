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
  <li><p>Slouží k specifikování samotných verzí šifrovacích algoritmů, jaké verze těchto algoritmů, session ID, certifikát od CA, master secret (i také premaster secret), is resumable (jestli se dá session znovu spustit), kompresních algortimů</p></li>
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
<br><br>

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
Tyto cíle se dokážou pomocí tzv. handshaku (posílání informací za účelem navázání spojení mezi dvěma stranami), tento handshake se skládá z devíti části, čtyři z toho jsou posílání přes socket
<br>
<ol>
  <li>client hello</li>
  <li>server hello</li>
  <li>authentication</li>
  <li>premaster secret</li>
  <li>private key used</li>
  <li>generate session keys</li>
  <li>client finished</li>
  <li>server finished</li>
  <li>TLS nakonfigurováno</li>
</ol>
<br>
<p>Taky existuje i TLS i asymetrickými šiframi - Diffie-Hellman key exchange</p>

<h1>Komunikace SSL/TLS</h1>
<pre>
-----   ClientHello
| C |   ---------\             -----
-----             -------------| S |
        ServerHello            -----
     __________________________|
     |                       
-----   Finished
| C | -----------\             -----
-----             -------------| S |
        Finished               -----
-----__________________________|
| C |
-----

  
TLS configurated


  
</pre> 


<h2>Appendix</h2>
<ul>
  <li>CA (Certificate Authority) = je důvěryhodná organizace, která vydává certifikáty (některé jsou více trusted, některé méně - méně trusted organizace)</li>
  <li>certifikát = "digitální průkaz" na internetu, který ověřuje že webový server patří opravdu webu a ne jen nějakému člověku</li>
  <li>MAC (Message Authentication Code) = je způsob ověření, že zpráva od klienta/serveru je autentická, je to hash klíče a zprávy , které se přidá do jiné hashovací funkce</li>
  <li>pre master secret = část dat, ze které se udělá master secret, vytvoří se tak že se skombinuje session key a náhodných 48 Bytes</li>
  <li>master secret = část dat, ze kterých se potom odvodí privátní klíče, HMAC (algoritmus pro MAC)..., vytvoří se z client random a server random a pre master secret</li>
  <li>clienet random/server random = náhodné 48 Bytes pro PMS (pre master secret, master secret)</li>
  <li>kontext v kryptografii = soubor paramterů pro správné fungování protokolu/operace</li>
</ul>

