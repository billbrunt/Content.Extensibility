iisreset /stop
md "C:\inetpub\TitusWebAdministration\CustomFunctions"
md "C:\inetpub\TitusWebAdministration\CustomFunctions\Content.Extensibility"
copy /y *.* "C:\inetpub\TitusWebAdministration\CustomFunctions\Content.Extensibility"
iisreset /start


