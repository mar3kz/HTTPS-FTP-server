<h1 align="center">Library nghttp2</h1>
<ul>
  <li>jak jsem už popisoval v NOTES_HTTP_PROTOCOL, tak implementace protokolu <strong>HTTP/2 podle RFC 9113</strong> (https://datatracker.ietf.org/doc/html/rfc9113) by bylo časově velice náročné, proto někdo sestavil tuto knihobnu zodpovědnou právě za tuto implementaci</li>
  <li>knihovna nghttp2 používá asynchronní IO operace a právě tyto operace si nehlídá sama, ale má na to knihovnu, která se jmenuje libevent</li>
  <li>proto tento projekt používá OpenSSL, což je open-source knihovna, která implementuje několik šifrovacích algoritmů, command-line nástrojů, ale hlavně implementuje SSL/TLS protokol, který je potřeba pro implementaci protokolu HTTP/2, což implementuje knihovna nghttp2, ale asynchronní operace na těchto socketech jsou zase ohlídané knihovnou libevent</li>
</ul>
<hr>
<h1 align="center">Libevent introduction</h1>
<ul>
  <li>knihovna, která poskytuje možnost zavolání callback funkcí, když se stane nějaký event na file descriptoru/ po dokončení timeoutu/po přijetí signálu</li>
  <li>poskytuje možnosti na DNS lookup (jako getaddrinfo)</li>
  <li>libevent má tzv. evbuffery/bufferevent, což zjednodušeně znamená, neprůhledný pointer na internal structuru, která má za úkol zjednodušit posílání/čtení dat z socketu, např. evbuffery na tohle jsou přesně dělané a buffereventy nabízejí ještě k tomu callbacky</li>
</ul>
<h2>Opaque pointers</h2>
<p>opaque = neprůhledný</p>
<p>v kostce toto znamená, že v hlavičkovém souboru můžeme mít nějaký datový typ (tímto myslím jenom struktury, unions - méně běžné nebo skrytí datového typu - obecně) a my budeme chtít používat tuto strukturu k nějakým věcem, ale třeba bychom nechtěli, aby někdo, kdo používal tento hlavičkový soubor přesně viděl, jak přesně náš kód funguje a všechny členy naší struktury, tak to uděláme tak, že v hlavičkovém souboru deklarujeme jenom pointer na tuto strukturu a samotné členy a fungování této struktury si ponecháme do .c souboru, kde vše bude naprogramované, tímto způsobem lidé nebudou vidět naše členy struktury</p>
