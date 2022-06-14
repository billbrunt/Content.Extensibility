net stop  "TITUS.Enterprise.Client.Service"
rem *************** Installing Custom Action **************************

md "C:\ProgramData\Titus\CustomFunctions"
md "C:\Program Files\Titus\Titus Services\EnterpriseClientService\CustomFunctions"
md "C:\Program Files\Titus\Titus Services\EnterpriseClientService\CustomFunctions\Content.Extensibility"
copy /y .\*.* "C:\Program Files\Titus\Titus Services\EnterpriseClientService\CustomFunctions\Content.Extensibility"


