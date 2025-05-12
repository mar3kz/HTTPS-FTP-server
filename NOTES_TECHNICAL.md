<h1 align="center">SSL/TLS</h1>
<p>SSL = Secure Sockets Layer (předchůdce TLS)</p>
<p>TLS = Transport Layer Security</p>
<p><strong>Jsou to protokoly, které používají různé šifrovací postupy za účelem bezpečné konverzace přes sockety</strong></p>
<p>Nejvíce se používají u HTTPS (HTTP over SSL/TLS), IoT, cloud, hry => všude, kde je potřeba bezpečné konverzace přes síť</p>
<p>Říká se SSL/TLS, jen protože je to z historických důvodů, jinak tento protokol se jmenuje TLS (Transport Layer Security)</p>
<br>
<p><strong>Protokol = Způsob/pravidla jak se data posílají přes socket, nic více! Jen údáva strukturu, taky i strukturu, jak i data vypadají FTP, HTTP, HTTP...</strong></p>
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
