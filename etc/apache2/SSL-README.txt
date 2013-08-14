To get SSL to work, you first have to generate a self-signed keypair. Follow step 2 of this guide: https://wiki.debian.org/Self-Signed_Certificate

Next, edit the port443 file in /etc/apache2/sites/available. It will look something like:

ErrorLog ${APACHE_LOG_DIR}/error.log
TransferLog ${APACHE_LOG_DIR}/access.log
#LogLevel debug

Listen 80

<VirtualHost *:80>
  DocumentRoot "/var/lib/bath/app"
  CustomLog ${APACHE_LOG_DIR}/bath.access.log combined

  <Location />
    DirectoryIndex index.py
    AddHandler mod_python .py
    PythonHandler mod_python.publisher

  </Location>

</VirtualHost>


Add the following lines to the file, inside the <VirtualHost> section:

  SSLEngine On
  SSLCertificateFile /etc/ssl/localcerts/apache.pem
  SSLCertificateKeyFile /etc/ssl/localcerts/apache.key

Change the port 80 to 443 as well, so that the file now looks like:

ErrorLog ${APACHE_LOG_DIR}/error.log
TransferLog ${APACHE_LOG_DIR}/access.log
#LogLevel debug

Listen 443

<VirtualHost *:443>
  SSLEngine On
  SSLCertificateFile /etc/ssl/localcerts/apache.pem
  SSLCertificateKeyFile /etc/ssl/localcerts/apache.key

  DocumentRoot "/var/lib/bath/app"
  CustomLog ${APACHE_LOG_DIR}/bath.access.log combined

  <Location />
    DirectoryIndex index.py
    AddHandler mod_python .py
    PythonHandler mod_python.publisher

  </Location>

</VirtualHost>
