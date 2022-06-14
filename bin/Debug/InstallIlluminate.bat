@echo NOTE: This should be installed while Illuminate is not running.
@echo       Check task manager for TITUS_IFS to see if running or other methods as desired to check if running.
@echo       Press Ctrl-C to terminate this install or any other key to continue.
pause
md "C:\Program Files\Titus\TITUS Illuminate\CustomFunctions"
md "C:\Program Files\Titus\TITUS Illuminate\CustomFunctions\Content.Extensibility"
copy /y *.* "C:\Program Files\Titus\TITUS Illuminate\CustomFunctions\Content.Extensibility"




