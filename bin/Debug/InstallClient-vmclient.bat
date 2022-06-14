taskkill /f /im Titus*
rem *************** Installing Custom Action **************************
rem md "C:\ProgramData\Titus\CustomActionFunctions"
md "C:\Program Files\Titus\Titus Services\EnterpriseClientService\CustomFunctions"
md "C:\Program Files\Titus\Titus Services\EnterpriseClientService\CustomFunctions\Content.Extensibility"
copy /y .\*.* "C:\Program Files\Titus\Titus Services\EnterpriseClientService\CustomFunctions\Content.Extensibility"
net start "TITUS.Enterprise.Client.Service"




