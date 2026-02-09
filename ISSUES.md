libevent ma bug - event_base po prijmuti dat od druhe strany proste nevola timeout event, i kdyz je v event_base, neni podpora pro multithreading, ale je tam zacatek pro to, data se neprijmou vsechny protoze max read je 4096, proto jsem chtel udelat timeout na to ze by se porad kontrolovalo, jestli se nemuze precist vice
struct timeval
kdyz se neco posle pres bufferevent_write() nebo precte pres bufferevent_read(), tak jeste pred tim nez se zavolaji tyto funkce, tak se uz spusti event_base_loop, coz znamena, ze tento thread by byll zasekly v select(), epoll() apod. a ceka se na nejaky event prave na underlying socketu, jediny event, ktery ta druha strana muze udelat je ukoncit socket, pokud se toto udela, select(), epoll() uvidi ze je novy event, tento se zaregistruje a potom se event_base_loop() zase podiva na eventy, ktere ma v event_base, kde uz je prave treba ten read/write a az potom se to udela, ale druha strana uz zavrela socket

nebo by client mohl posilat vzdy 2 zpravy aby jedna se zaregistrovala a ta druha by slouzila pro precteni, toto je ale implementacne tezke a zbytecne, proto diky Bohu, se muze udelat persistivni TIMEOUT event, ktery v event_base zustane a bude se pripominat podle toho, jak se nastavi struktura timeval
nebo bych mohl udelat \' ale na to by bylo prohledavani zase kazdeho radku
a kdyz jsem delal cteni ze stdin tak to taky nejak nefungovalo, nesel myslim nejak zavrit stdin
ale mozna chunked reading by fungovalo

jedine co funguje je tohle a funguje to protoze v C v snprintf se neda udelat opravdovy novy radek jen \n, coz vezme shell jako znak, proto to spolehlive funguje jenom v interaktivnim shellu, taky pokud by shell chtel zmenit nejake promenne v uvozovkach, tak jedine v "", ale to by zase neslo v C v snprintf, protoze to by si myslelo, ze je ukonceny string, ale i pres to vsechno se to nejak do toho stdin da dat ale nezaregistruje se EEOF na konci heredoc, moz se by slo udelat cteni po chunkach...
zsh -c 'python3 PYTHON/dynamicke_tabulky.py arg' << EOF
>quote NOVY OPRAVDOVY RADEK A TADY POTREBUJU PASTENOUT TEN TREE -H $ (tim ze udelam ctrl v - musi to byt na novem radku - jinak to nefunguje!!)
obsaah
obsah
obsah to EOF muze byt i tady
EOF'

ALE JE DULEZITE ZE U TOHO PRVNIHO JE OPRAVDOVY RADEK A NE JEN \n
a nekdy to hazelo command list too long
takze skoro nemozne, proto je lepsi nejaky file

+ 301, 303 existuje - HTTP
