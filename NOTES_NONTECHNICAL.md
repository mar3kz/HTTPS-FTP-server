licence = právní podmínky, za kterých se nějaká činnost může vykonávat/nějaký produkt používat (v tomto případě software)

x.h.in = header file s dynamickými placeholdery (jako f string v Pythonu, kde v {} jsou názvy prostředí, PATHs apod.) => po stažení se tento header file vloží sám do systému pomocí tich dynamických placeholderů a stane se z něho jenom header file

.md = markdown file, na úpravu textu (mohou tam být i tagy jako v HTML

HTTPS = požadavky HTTP šifrované přes SSL/TLS, ale pořád je to HTTP!

127.0.0.1:8000/http://127.0.0.1:8000 => HTTP
https://127.0.0.1:8000 => HTTPS

na public web serverech se to většinou přepne do HTTPS (pokud to ten web server podporuje), ale k lokální adrese je to defaultní pro HTTP (protože se neočekává, že localhost bude používat x509 certifikát), proto kdybych chtěl opravdu použít HTTPS protokol, tak to musím explicitně specifikovat
