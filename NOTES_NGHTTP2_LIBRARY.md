<h1 align="center">Library nghttp2</h1>
<p>jak jsem už popisoval v NOTES_HTTP_PROTOCOL, tak implementace protokolu <strong>HTTP/2 podle RFC 9113</strong> (https://datatracker.ietf.org/doc/html/rfc9113) by bylo časově velice náročné, proto někdo sestavil tuto knihobnu zodpovědnou právě za tuto implementaci</p>
<p>knihovna nghttp2 používá asynchronní IO operace a právě tyto operace si nehlídá sama, ale má na to knihovnu, která se jmenuje libevent</p>
<p>proto tento projekt používá OpenSSL, což je open-source knihovna, která implementuje několik šifrovacích algoritmů, command-line nástrojů, ale hlavně implementuje SSL/TLS protokol, který je potřeba pro implementaci protokolu HTTP/2, což implementuje knihovna nghttp2, ale asynchronní operace na těchto socketech jsou zase ohlídané knihovnou libevent</p>
<br>
<hr>
<h1 align="center">Libevent introduction</h1>
<>
