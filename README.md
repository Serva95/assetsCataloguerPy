# Setup guide

## Python dependencies
To install Python dependencies:

    pip install -r requirements.txt

You may also need to install <code> pymysql </code>, in which case the command is:

    pip install pymysql

## Database
MySQL must be installed on the machine. For example, in the case of an Ubuntu distribution:

    sudo apt install mysql-server

A user for the database must be created with a name of your choice (at the moment, in the program, the user name is "external", just change it in the code according to the user created).

After choosing the password for the created user, write it in the appropriate code variable.

### Database and Tables
Next you will have to create a database called "ip"; after that, create a table (in the "ip" database) called "communications" with the following code:
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
You will need Tshark available in the PATH of your machine. To do this, you can install the entire Wireshark suite. In case of an Ubuntu distribution with the command:

    sudo apt install wireshark
    
