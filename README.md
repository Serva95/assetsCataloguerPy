# Guida al setup

## Dipendenze Python
Per installare le dipendenze di Python:

    pip install -r requirements.txt

Può essere necessario installare anche <code>pymysql</code>, in quel caso il
comando è:

    pip install pymysql

## Database
Sulla macchina in esecuzione dovrà essere installato MySQL. Ad esempio, nel
caso di una distribuzione Ubuntu:

    sudo apt install mysql-server

Dovrà essere creato un utente per il database con nome a scelta
(al momento, nel programma, il nome utente è "external", basta cambiarlo
nel codice a seconda dell'utente creato).

Scelta la password per l'utente creato, scriverla nell'apposita variabile
nel codice.

### Database e Tabelle
Successivamente si dovrà creare un database chiamato "ip"; fatto ciò,
creare una tabella (nel database "ip") chiamata "communications"
con il seguente codice:
<pre>
CREATE TABLE `communications` (
  `id` int UNSIGNED NOT NULL AUTO_INCREMENT,
  `src_ip4` varchar(16) DEFAULT NULL,
  `dest_ip4` varchar(16) DEFAULT NULL,
  `src_ip6` varchar(32) DEFAULT NULL,
  `dest_ip6` varchar(32) DEFAULT NULL,
  `src_mac` varchar(17) DEFAULT NULL,
  `dest_mac` varchar(17) DEFAULT NULL,
  `src_port` smallint(5) UNSIGNED DEFAULT NULL,
  `dest_port` smallint(5) UNSIGNED DEFAULT NULL,
  `proto` varchar(32) DEFAULT NULL,
  `flags` varchar(10) DEFAULT NULL,
  `first_seen` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_seen` timestamp NULL DEFAULT NULL
)
</pre>


## Tshark
Sarà necessario avere Tshark disponibile nel PATH della propria macchina.
Per farlo è possibile installare l'intera suite Wireshark. Nel caso di una
distribuzione Ubuntu:

    sudo apt install wireshark
    
