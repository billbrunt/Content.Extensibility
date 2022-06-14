using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Security.Cryptography;  //MD5
using System.Text.RegularExpressions;
using Titus.Extensibility;
using System.Data.SqlClient;

using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
//using SimpleImpersonation;
using System.Runtime.InteropServices;

using System.Windows.Forms;

namespace Content.Extensibility
{
    public class QueryFile : ICustomDynamicFunction
    {
        #region from 
        public static void ActivateWindow(IntPtr mainWindowHandle)
        {
            //check if already has focusif (mainWindowHandle == GetForegroundWindow())  return;

            //check if window is minimizedif (IsIconic(mainWindowHandle))
            {
                ShowWindow(mainWindowHandle, Restore);
            }

            // Simulate a key press
            keybd_event((byte)ALT, 0x45, EXTENDEDKEY | 0, 0);

            //SetForegroundWindow(mainWindowHandle);// Simulate a key release
            keybd_event((byte)ALT, 0x45, EXTENDEDKEY | KEYUP, 0);

            SetForegroundWindow(mainWindowHandle);


        }
        #endregion
        #region https://stackoverflow.com/questions/2636721/bring-another-processes-window-to-foreground-when-it-has-showintaskbar-false
        public static void BringProcessToFront(Process process)
        {
            //IntPtr handle = process.MainWindowHandle;
            //if (IsIconic(handle))
            //{
            //    ShowWindow(handle, SW_RESTORE);
            //}
            //SetForegroundWindow(handle);
            IntPtr mainWindowHandle = process.MainWindowHandle;
            if (mainWindowHandle == GetForegroundWindow()) return;

            //check if window is minimized if (IsIconic(mainWindowHandle))
            {
                ShowWindow(mainWindowHandle, Restore);
            }

            // Simulate a key press
            keybd_event(0, 0, 0, 0);

            SetForegroundWindow(mainWindowHandle);
        }
        private const int ALT = 0xA4;
        private const int EXTENDEDKEY = 0x1;
        private const int KEYUP = 0x2;
        private const uint Restore = 9;

        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, int dwExtraInfo);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern int ShowWindow(IntPtr hWnd, uint Msg);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        #endregion
        #region Start of code copided from: https://social.msdn.microsoft.com/Forums/en-US/0c0ca087-5e7b-4046-93cb-c7b3e48d0dfb/how-run-client-application-as-a-windows-service-in-c?forum=csharpgeneral
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }



        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_ATTRIBUTES
        {
            public uint nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;

        }

        internal enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        internal enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        public class ProcessAsUser
        {

            [DllImport("advapi32.dll", SetLastError = true)]
            private static extern bool CreateProcessAsUser(
                IntPtr hToken,
                string lpApplicationName,
                string lpCommandLine,
                ref SECURITY_ATTRIBUTES lpProcessAttributes,
                ref SECURITY_ATTRIBUTES lpThreadAttributes,
                bool bInheritHandles,
                uint dwCreationFlags,
                IntPtr lpEnvironment,
                string lpCurrentDirectory,
                ref STARTUPINFO lpStartupInfo,
                out PROCESS_INFORMATION lpProcessInformation);


            [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx", SetLastError = true)]
            private static extern bool DuplicateTokenEx(
                IntPtr hExistingToken,
                uint dwDesiredAccess,
                ref SECURITY_ATTRIBUTES lpThreadAttributes,
                Int32 ImpersonationLevel,
                Int32 dwTokenType,
                ref IntPtr phNewToken);


            [DllImport("advapi32.dll", SetLastError = true)]
            private static extern bool OpenProcessToken(
                IntPtr ProcessHandle,
                UInt32 DesiredAccess,
                ref IntPtr TokenHandle);

            [DllImport("userenv.dll", SetLastError = true)]
            private static extern bool CreateEnvironmentBlock(
                    ref IntPtr lpEnvironment,
                    IntPtr hToken,
                    bool bInherit);


            [DllImport("userenv.dll", SetLastError = true)]
            private static extern bool DestroyEnvironmentBlock(
                    IntPtr lpEnvironment);

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern bool CloseHandle(
                IntPtr hObject);

            private const short SW_SHOW = 5;
            private const uint TOKEN_QUERY = 0x0008;
            private const uint TOKEN_DUPLICATE = 0x0002;
            private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
            private const int GENERIC_ALL_ACCESS = 0x10000000;
            private const int STARTF_USESHOWWINDOW = 0x00000001;
            private const int STARTF_FORCEONFEEDBACK = 0x00000040;
            private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;


            private static bool LaunchProcessAsUser(string cmdLine, IntPtr token, IntPtr envBlock)
            {
                bool result = false;


                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                SECURITY_ATTRIBUTES saProcess = new SECURITY_ATTRIBUTES();
                SECURITY_ATTRIBUTES saThread = new SECURITY_ATTRIBUTES();
                saProcess.nLength = (uint)Marshal.SizeOf(saProcess);
                saThread.nLength = (uint)Marshal.SizeOf(saThread);

                STARTUPINFO si = new STARTUPINFO();
                si.cb = (uint)Marshal.SizeOf(si);


                //if this member is NULL, the new process inherits the desktop
                //and window station of its parent process. If this member is
                //an empty string, the process does not inherit the desktop and
                //window station of its parent process; instead, the system
                //determines if a new desktop and window station need to be created.
                //If the impersonated user already has a desktop, the system uses the
                //existing desktop.

                si.lpDesktop = @"WinSta0\Default"; //Modify as needed
                si.dwFlags = STARTF_USESHOWWINDOW | STARTF_FORCEONFEEDBACK;
                si.wShowWindow = SW_SHOW;
                //Set other si properties as required.

                result = CreateProcessAsUser(
                    token,
                    null,
                    cmdLine,
                    ref saProcess,
                    ref saThread,
                    false,
                    CREATE_UNICODE_ENVIRONMENT,
                    envBlock,
                    null,
                    ref si,
                    out pi);


                if (result == false)
                {
                    int error = Marshal.GetLastWin32Error();
                    string message = String.Format("CreateProcessAsUser Error: {0}", error);
                    Debug.WriteLine(message);

                }

                return result;
            }


            private static IntPtr GetPrimaryToken(int processId)
            {
                IntPtr token = IntPtr.Zero;
                IntPtr primaryToken = IntPtr.Zero;
                bool retVal = false;
                Process p = null;

                try
                {
                    p = Process.GetProcessById(processId);
                }

                catch (ArgumentException)
                {

                    string details = String.Format("ProcessID {0} Not Available", processId);
                    Debug.WriteLine(details);
                    throw;
                }


                //Gets impersonation token
                retVal = OpenProcessToken(p.Handle, TOKEN_DUPLICATE, ref token);
                if (retVal == true)
                {

                    SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                    sa.nLength = (uint)Marshal.SizeOf(sa);

                    //Convert the impersonation token into Primary token
                    retVal = DuplicateTokenEx(
                        token,
                        TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
                        ref sa,
                        (int)SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                        (int)TOKEN_TYPE.TokenPrimary,
                        ref primaryToken);

                    //Close the Token that was previously opened.
                    CloseHandle(token);
                    if (retVal == false)
                    {
                        string message = String.Format("DuplicateTokenEx Error: {0}", Marshal.GetLastWin32Error());
                        Debug.WriteLine(message);
                    }

                }

                else
                {

                    string message = String.Format("OpenProcessToken Error: {0}", Marshal.GetLastWin32Error());
                    Debug.WriteLine(message);

                }

                //We'll Close this token after it is used.
                return primaryToken;

            }

            private static IntPtr GetEnvironmentBlock(IntPtr token)
            {

                IntPtr envBlock = IntPtr.Zero;
                bool retVal = CreateEnvironmentBlock(ref envBlock, token, false);
                if (retVal == false)
                {

                    //Environment Block, things like common paths to My Documents etc.
                    //Will not be created if "false"
                    //It should not adversley affect CreateProcessAsUser.

                    string message = String.Format("CreateEnvironmentBlock Error: {0}", Marshal.GetLastWin32Error());
                    Debug.WriteLine(message);

                }
                return envBlock;
            }

            public static bool Launch(string appCmdLine /*,int processId*/)
            {

                bool ret = false;

                //Either specify the processID explicitly
                //Or try to get it from a process owned by the user.
                //In this case assuming there is only one explorer.exe

                Process[] ps = Process.GetProcessesByName("explorer");
                int processId = -1;//=processId
                if (ps.Length > 0)
                {
                    processId = ps[0].Id;
                }

                if (processId > 1)
                {
                    IntPtr token = GetPrimaryToken(processId);

                    if (token != IntPtr.Zero)
                    {

                        IntPtr envBlock = GetEnvironmentBlock(token);
                        ret = LaunchProcessAsUser(appCmdLine, token, envBlock);
                        if (envBlock != IntPtr.Zero)
                            DestroyEnvironmentBlock(envBlock);

                        CloseHandle(token);
                    }

                }
                return ret;
            }

        }
        #endregion
        public IList<string> GetRequiredParameters()
        {
            return new List<string>
                                {
                                    "Function",
                                    "Parameter1",
                                    "Parameter2",
                                    "Parameter3",
                                    "Parameter4",
                                    "Parameter5",
                                    "Parameter6",
                                    "Parameter7",
                                    "Parameter8",
                                    "Parameter9",
                                    "Parameter10",
                                    "Parameter11",
                                    "Parameter12",
                                    "Parameter13",
                                    "Parameter14",
                                    "Parameter15",
                                    "EnableLogging",
                                    "Configuration",
                                    "Rule",
                                    "DynamicProperty"
                                };
        }
        public IList<string> GetExecutionResultProperties()
        {
            return new List<string> {
                                    "Function",
                                    "Parameter1",
                                    "Parameter2",
                                    "Parameter3",
                                    "Parameter4",
                                    "Parameter5",
                                    "Parameter6",
                                    "Parameter7",
                                    "Parameter8",
                                    "Parameter9",
                                    "Parameter10",
                                    "Parameter11",
                                    "Parameter12",
                                    "Parameter13",
                                    "Parameter14",
                                    "Parameter15",
                                    "Result",
                                    "ReturnCode",
                                    "Message",
                                    "Version",
                                    "Runtime"
                                };
        }

        static bool fncBolGetContents(
            ref string psStrReturnCode,
            ref string psStrContents,
            string psStrSoftwareRunning,
            string psStrLoggingEnabled,
            string psStrExtendedLoggingEnabled)
        {
            if (psStrContents.Substring(0, 1) == "@" && psStrSoftwareRunning == "ConsoleApp1.exe")
            {
                try
                {
                    psStrContents = psStrContents.Substring(1, psStrContents.Length - 1);
                    psStrContents = Path.Combine(Directory.GetCurrentDirectory(), psStrContents);
                    if (File.Exists(psStrContents))
                    {
                        psStrContents = File.ReadAllText(psStrContents);
                    }
                    else
                    {
                        psStrReturnCode = "1";
                        psStrContents = $"It looks like the file {psStrContents} does not exist. Please check the path, filename and extension.";
                        //Log.Error(psStrContents);
                        return false;
                    }
                }
                catch
                {
                    psStrReturnCode = "2";
                    psStrContents = "Unknown exception in fncBolGetContents. Turn on logging for more information.";
                    //Log.Error(ex, $"Could not open {psStrContents}");
                    return false;
                }
            }
            return true;
        }
        public string GetAppSetting(Configuration config, string key)
        {
            KeyValueConfigurationElement element = config.AppSettings.Settings[key];
            if (element != null)
            {
                string value = element.Value;
                if (!string.IsNullOrEmpty(value))
                    return value;
            }
            return string.Empty;
        }
        public bool Execute(string dataDirectory,
            IList<string> parameters,
            IDictionary<string, string> resultContainer,
            out string resultMessage)
        {
            var lsVarEnd = 0.0;
            var lsVarStart = (DateTime.Now - DateTime.MinValue).TotalMilliseconds;

            String lsStrFunction = parameters[0];
            String lsStrParameter1 = parameters[1];
            String lsStrParameter2 = parameters[2];
            String lsStrParameter3 = parameters[3];
            String lsStrParameter4 = parameters[4];
            String lsStrParameter5 = parameters[5];
            String lsStrParameter6 = parameters[6];
            String lsStrParameter7 = parameters[7];
            String lsStrParameter8 = parameters[8];
            String lsStrParameter9 = parameters[9];
            String lsStrParameter10 = parameters[10];
            String lsStrParameter11 = parameters[11];
            String lsStrParameter12 = parameters[12];
            String lsStrParameter13 = parameters[13];
            String lsStrParameter14 = parameters[14];
            String lsStrParameter15 = parameters[15];
            String lsStrLoggingEnabled = parameters[16];
            String lsStrConfiguration = parameters[17];
            String lsStrRuleName = parameters[18];
            String lsStrDynamicProperty = parameters[19];
            String lsStrSoftwareRunning = "Content.Extensibility.dll";
            String lsStrConfigObject = String.Concat(lsStrRuleName, "/", lsStrDynamicProperty, "/", lsStrSoftwareRunning);
            string lsStrExtendedLoggingEnabled = "0";

            string lsStrMessage = "Status is all good.";
            string lsStrResult = "";
            string lsStrReturnCode = "0";
            string lsStrVersionNo = "";
            string strConfigPath = this.GetType().Assembly.Location;
            //-----------------------------------------------------------------------------------------------------------------------------------------------------//
            //-----------------------------------------   START OF SET WHICH GETS COPIED AS CUSTOM DYNAMIC PROPERTY   ---------------------------------------------//
            //-----------------------------------------------------------------------------------------------------------------------------------------------------//
            #region Code to copy and paste between Console and DLL
            lsStrVersionNo = "2022.06.06.09.36";
            // string strConfigPath = Main.GetType().Assembly.Location;
            #region Error check   1 Try and open App.config
            //try
            //{
            //    lsStrMessage = "Error check   1 Try and open App.config";
            //    config = ConfigurationManager.OpenExeConfiguration(strConfigPath);
            //}
            //catch (System.Exception ex)
            //{
            //    if (lsStrLoggingEnabled.ToUpper() == "TRUE")
            //    {
            //        //Log.Error($"{lsStrConfigObject} Error with +. More details available from extended logging.");
            //        if (lsStrExtendedLoggingEnabled == "1")
            //        {
            //            //Log.Error(String.Concat(lsStrConfigObject, " ", ex.ToString()));
            //        }
            //    }
            //    lsStrMessage = String.Concat(lsStrMessage, "\n", "Oops. It was caught inside + with:", "\n");
            //    lsStrMessage = String.Concat(lsStrMessage, ex.ToString());
            //}
            #endregion
            #region some debug Console.WriteLine 
            //Console.WriteLine("*********************** At the top of {0} ********************************************", lsStrSoftwareRunning);
            //Console.WriteLine("***                                                                               ****");
            //Console.WriteLine("***                                                               lsStrFunction  = {0}", lsStrFunction);
            //Console.WriteLine("***                                                             lsStrParameter1  = {0}", lsStrParameter1);
            //Console.WriteLine("***                                                             lsStrParameter2  = {0}", lsStrParameter2);
            //Console.WriteLine("***                                                             lsStrParameter3  = {0}", lsStrParameter3);
            //Console.WriteLine("***                                                             lsStrParameter4  = {0}", lsStrParameter4);
            //Console.WriteLine("***                                                             lsStrParameter5  = {0}", lsStrParameter5);
            //Console.WriteLine("***                                                             lsStrParameter6  = {0}", lsStrParameter6);
            //Console.WriteLine("***                                                             lsStrParameter7  = {0}", lsStrParameter7);
            //Console.WriteLine("***                                                             lsStrParameter8  = {0}", lsStrParameter8);
            //Console.WriteLine("***                                                             lsStrParameter9  = {0}", lsStrParameter9);
            //Console.WriteLine("***                                                             lsStrParameter10 = {0}", lsStrParameter10);
            //Console.WriteLine("***                                                             lsStrParameter11 = {0}", lsStrParameter11);
            //Console.WriteLine("***                                                             lsStrParameter12 = {0}", lsStrParameter12);
            //Console.WriteLine("***                                                             lsStrParameter13 = {0}", lsStrParameter13);
            //Console.WriteLine("***                                                             lsStrParameter14 = {0}", lsStrParameter14);
            //Console.WriteLine("***                                                             lsStrParameter15 = {0}", lsStrParameter15);
            //Console.WriteLine("***                                                                          ****");
            //Console.WriteLine("***                                                                          ****");
            //string lsStrReadLine = "";
            #endregion
            bool lsBolExceptionTrapped = false;
            bool lsBolValidFunction = false;
            // Enabling logging if needed
            if (lsStrLoggingEnabled.ToUpper() == "TRUE")  // Is Logging enabled?
            {
                // Open the logger
                // https://stackify.com/nlog-vs-log4net-vs-serilog/
                //Log.Logger = new LoggerConfiguration()
                //               .MinimumLevel.Debug()
                //                .WriteTo.File(@"C:\ProgramData\TITUS\CustomResources\Content.Extensibility\Content.Extensibility..log", rollingInterval: RollingInterval.Day)
                //               .CreateLogger();
                // lsVarEnd = (DateTime.Now - DateTime.MinValue).TotalMilliseconds;
                //Log.Debug($"{lsStrConfigObject} Starting up - Content.Extensibility Version: {lsStrVersionNo}  ******************************");
                //Log.Debug($"{lsStrConfigObject} Reading logging level settings from registry");
                // Determine if extended logging is on
                string lsStrExtendedLoggingEnabledRegKey = lsStrSoftwareRunning == "ConsoleApp1.exe" ? @"SOFTWARE\WOW6432Node\TITUS\CustomFunctions\Content.Extensibility" : @"SOFTWARE\TITUS\CustomFunctions\Content.Extensibility";
                try
                {
                    // Log.Debug($@"{lsStrConfigObject} Going to read Computer\HKEY_LOCAL_MACHINE\{lsStrExtendedLoggingEnabledRegKey}");
                    // would like to get this to work...
                    //--------- https://stackoverflow.com/questions/41558433/c-sharp-reading-registry-key-value-key-is-always-null
                    //---------
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(lsStrExtendedLoggingEnabledRegKey))
                    {
                        //Log.Debug(String.Concat($"{lsStrConfigObject}", @" (key != null) evaluates to ", $"{ key != null}"));
                        if (key != null)
                        {
                            //Log.Debug(String.Concat($"{lsStrConfigObject}", @" (key != null) evaluates to ", $"True"));
                            Object k = key.GetValue("ExtendedLoggingEnabled");  // Value for this registry key should be 0 or 1 to be consistent with other registry settings.
                            if (k != null)
                            {
                                lsStrExtendedLoggingEnabled = k.ToString();
                                //Log.Debug($"{lsStrConfigObject}", @"lsStrExtendedLoggingEnabled = ", $"{lsStrExtendedLoggingEnabled}");
                            }
                        }
                        else
                        {
                            //Log.Debug(String.Concat($"{lsStrConfigObject}", " Registry not read."));
                        }

                    }
                }
                catch  //just for demonstration...it's always best to handle specific exceptions
                {
                    //react appropriately
                    if (lsStrLoggingEnabled.ToUpper() == "TRUE")
                    {
                        //Log.Debug(String.Concat(lsStrConfigObject, " ", @"Catch from Determine extended logging value from HKLM\SOFTWARE\TITUS\CustomFunctions\Content.Extensibility"));
                        //Log.Debug(String.Concat(lsStrConfigObject, " ", ex, "Exception {0}"));
                    }
                }
                //Log.Debug(String.Concat(lsStrConfigObject, " ", $"Read  {lsStrExtendedLoggingEnabledRegKey}"));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "ExtendedLoggingEnabled = ", lsStrExtendedLoggingEnabled));

            }
            // Write input values if extended logging on
            if (lsStrLoggingEnabled.ToUpper() == "TRUE" && lsStrExtendedLoggingEnabled == "1")
            {
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrFunction          = ", lsStrFunction));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrParameter1        = ", lsStrParameter1));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrParameter2        = ", lsStrParameter2));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrParameter3        = ", lsStrParameter3));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrParameter4        = ", lsStrParameter4));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrParameter5        = ", lsStrParameter5));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrParameter6        = ", lsStrParameter6));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrParameter7        = ", lsStrParameter7));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrParameter8        = ", lsStrParameter8));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrParameter9        = ", lsStrParameter9));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrParameter10       = ", lsStrParameter10));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrParameter11       = ", lsStrParameter11));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrParameter12       = ", lsStrParameter12));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrParameter13       = ", lsStrParameter13));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrParameter14       = ", lsStrParameter14));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrParameter15       = ", lsStrParameter15));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrLoggingEnabled    = ", lsStrLoggingEnabled));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrConfiguration     = ", lsStrConfiguration));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrRuleName          = ", lsStrRuleName));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "lsStrDynamicProperty   = ", lsStrDynamicProperty));
            }
            // Math operators of: + -  * /
            if (lsStrFunction.ToUpper() == "+" || lsStrFunction.ToUpper() == "-" || lsStrFunction.ToUpper() == "*" || lsStrFunction.ToUpper() == @"/")
            {
                float lsfltnum1 = 0;
                float lsfltnum2 = 0;
                float lsfltnum3 = 0;
                float lsfltnum4 = 0;
                float lsfltnum5 = 0;
                float lsfltnum6 = 0;
                float lsfltnum7 = 0;
                float lsfltnum8 = 0;
                float lsfltnum9 = 0;
                float lsfltnum10 = 0;
                try
                {
                    if (lsStrLoggingEnabled.ToUpper() == "TRUE")
                    {
                        //Log.Debug($"{lsStrConfigObject} About to convert all the lsStrParameterN from strings to floats;");
                    }
                    try
                    {
                        float lsfltdefault = 1;
                        if (lsStrFunction.ToUpper() == "*" || lsStrFunction.ToUpper() == @"/")
                        {
                            lsfltdefault = 1;
                        }
                        if (lsStrFunction.ToUpper() == "+" || lsStrFunction.ToUpper() == "-")
                        {
                            lsfltdefault = 0;
                        }
                        lsfltnum1 = lsStrParameter1 == "" ? lsfltdefault : float.Parse(lsStrParameter1);
                        lsfltnum2 = lsStrParameter2 == "" ? lsfltdefault : float.Parse(lsStrParameter2);
                        lsfltnum3 = lsStrParameter3 == "" ? lsfltdefault : float.Parse(lsStrParameter3);
                        lsfltnum4 = lsStrParameter4 == "" ? lsfltdefault : float.Parse(lsStrParameter4);
                        lsfltnum5 = lsStrParameter5 == "" ? lsfltdefault : float.Parse(lsStrParameter5);
                        lsfltnum6 = lsStrParameter6 == "" ? lsfltdefault : float.Parse(lsStrParameter6);
                        lsfltnum7 = lsStrParameter7 == "" ? lsfltdefault : float.Parse(lsStrParameter7);
                        lsfltnum8 = lsStrParameter8 == "" ? lsfltdefault : float.Parse(lsStrParameter8);
                        lsfltnum9 = lsStrParameter9 == "" ? lsfltdefault : float.Parse(lsStrParameter9);
                        lsfltnum10 = lsStrParameter10 == "" ? lsfltdefault : float.Parse(lsStrParameter10);
                    }
                    catch (System.FormatException)
                    {
                        lsStrResult = $"The {lsStrFunction} function errored. Check that all your ParametersN are valid numbers and format.";
                        //Log.Error($"{lsStrConfigObject} {lsStrResult}");
                        lsBolExceptionTrapped = true;
                        lsStrReturnCode = @"+-*/2"; //Value for invalid number as parameter to + function.

                    }
                    if (lsStrLoggingEnabled.ToUpper() == "TRUE")
                    {
                        //Log.Debug($"{lsStrConfigObject} After parameters converted to float.");
                        //Log.Debug($"{lsStrConfigObject} About to run {lsStrFunction}.");

                    }
                    if (lsBolExceptionTrapped == false)
                    {
                        float lsfltResult = 0;
                        if (lsStrFunction == "+")
                        {
                            lsfltResult = lsfltnum1 + lsfltnum2 + lsfltnum3 + lsfltnum4 + lsfltnum5 + lsfltnum6 + lsfltnum7 + lsfltnum8 + lsfltnum9 + lsfltnum10;
                        }
                        if (lsStrFunction == "-")
                        {
                            lsfltResult = lsfltnum1 - lsfltnum2 - lsfltnum3 - lsfltnum4 - lsfltnum5 - lsfltnum6 - lsfltnum7 - lsfltnum8 - lsfltnum9 - lsfltnum10;
                        }
                        if (lsStrFunction == "*")
                        {
                            lsfltResult = lsfltnum1 * lsfltnum2 * lsfltnum3 * lsfltnum4 * lsfltnum5 * lsfltnum6 * lsfltnum7 * lsfltnum8 * lsfltnum9 * lsfltnum10;
                        }
                        if (lsStrFunction == @"/")
                        {
                            lsfltResult = lsfltnum1 / lsfltnum2;
                            lsfltResult = lsfltResult / lsfltnum3;
                            lsfltResult = lsfltResult / lsfltnum4;
                            lsfltResult = lsfltResult / lsfltnum5;
                            lsfltResult = lsfltResult / lsfltnum6;
                            lsfltResult = lsfltResult / lsfltnum7;
                            lsfltResult = lsfltResult / lsfltnum8;
                            lsfltResult = lsfltResult / lsfltnum9;
                            lsfltResult = lsfltResult / lsfltnum10;
                        }
                        if (lsStrLoggingEnabled.ToUpper() == "TRUE")
                        {
                            //Log.Debug($"{lsStrConfigObject} After {lsStrFunction}.");
                        }
                        lsStrResult = lsfltResult.ToString();
                    }
                    else
                    {
                        //Log.Error($"{lsStrConfigObject} {lsStrFunction} never ran because of error above.");
                    }
                }
                catch (Exception ex)
                {
                    if (lsStrLoggingEnabled.ToUpper() == "TRUE")
                    {
                        //Log.Error($"{lsStrConfigObject} Error with +. More details available from extended logging.");
                        if (lsStrExtendedLoggingEnabled == "1")
                        {
                            //Log.Error(String.Concat(lsStrConfigObject, " ", ex.ToString()));
                        }
                    }
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Oops. It was caught inside + with:", "\n");
                    lsStrMessage = String.Concat(lsStrMessage, ex.ToString());
                    lsBolExceptionTrapped = true;
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "ASC")
            {
                string lsStrTextToProcess = lsStrParameter1;
                lsBolExceptionTrapped = fncBolGetContents(ref lsStrReturnCode, ref lsStrTextToProcess, lsStrSoftwareRunning, lsStrLoggingEnabled, lsStrExtendedLoggingEnabled) ? false : true;
                if (lsBolExceptionTrapped == true)
                {
                    lsStrMessage = lsStrTextToProcess;
                }
                else
                {
                    foreach (byte b in System.Text.Encoding.UTF8.GetBytes(lsStrTextToProcess.ToCharArray()))
                        lsStrResult = $"{lsStrResult}{b.ToString()} ";
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "LUHN")
            {

                if (LuhnValidator.Validate(lsStrParameter1))
                {
                    Console.WriteLine("Valid");

                }
                else
                {
                    Console.WriteLine("Invalid");
                }

            }
            if (lsStrFunction.ToUpper() == "CHARLIST")
            {
                // ConsoleApp1 CHARLIST 65,66,67,68
                // ABCD
                // Above is the result.
                //
                string[] words = lsStrParameter1.Split(',');

                string text = "";
                foreach (var word in words)
                {
                    int asciiCode = Int32.Parse(word);
                    char character = (char)asciiCode;
                    text = String.Concat(text, character.ToString());
                }
                lsStrResult = text;
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "CONSOLEAPP1")  //Call ConsoleApp1
            {
                try
                {
                    string lsStrPathToConsleApp = lsStrParameter2 == "" ? @"C:\Program Files\TITUS\TITUS Illuminate\CustomFunctions\Content.Extensibility\" : lsStrParameter2;
                    string lsStrDQ = @"""";
                    string lsStrConsoleAppWorkingDir = lsStrParameter3;
                    string lsStrArguments = "";
                    lsStrArguments = string.Concat(lsStrArguments, @"/c start ", lsStrDQ, lsStrDQ, lsStrPathToConsleApp, "ConsoleApp1.exe", lsStrDQ, " ");      // What to call
                    lsStrArguments = string.Concat(lsStrArguments, lsStrDQ, lsStrParameter1, lsStrDQ, " ");
                    lsStrArguments = string.Concat(lsStrArguments, lsStrDQ, lsStrParameter4, lsStrDQ, " ");
                    lsStrArguments = string.Concat(lsStrArguments, lsStrDQ, lsStrParameter5, lsStrDQ, " ");
                    lsStrArguments = string.Concat(lsStrArguments, lsStrDQ, lsStrParameter6, lsStrDQ, " ");
                    lsStrArguments = string.Concat(lsStrArguments, lsStrDQ, lsStrParameter7, lsStrDQ, " ");
                    lsStrArguments = string.Concat(lsStrArguments, lsStrDQ, lsStrParameter8, lsStrDQ, " ");
                    lsStrArguments = string.Concat(lsStrArguments, lsStrDQ, lsStrParameter9, lsStrDQ, " ");
                    lsStrArguments = string.Concat(lsStrArguments, lsStrDQ, lsStrParameter10, lsStrDQ, " ");
                    lsStrArguments = string.Concat(lsStrArguments, lsStrDQ, lsStrParameter11, lsStrDQ, " ");
                    lsStrArguments = string.Concat(lsStrArguments, lsStrDQ, lsStrParameter12, lsStrDQ, " ");
                    lsStrArguments = string.Concat(lsStrArguments, lsStrDQ, lsStrParameter13, lsStrDQ, " ");
                    lsStrArguments = string.Concat(lsStrArguments, lsStrDQ, lsStrParameter14, lsStrDQ, " ");
                    lsStrArguments = string.Concat(lsStrArguments, lsStrDQ, lsStrParameter15, lsStrDQ, lsStrDQ);

                    Console.WriteLine("lsStrArguments  = \n {0}", lsStrArguments);

                    String command = lsStrArguments;
                    String lsStrConsoleAppLog = @"C:\users\public\ConsoleApp1.log";
                    ProcessStartInfo cmdsi = new ProcessStartInfo("cmd.exe");
                    cmdsi.Arguments = command;
                    cmdsi.RedirectStandardOutput = true; // added xx
                    cmdsi.UseShellExecute = false; // added xx
                    cmdsi.WorkingDirectory = lsStrConsoleAppWorkingDir;
                    Process cmd1 = Process.Start(cmdsi);
                    //cmd1.WaitForExit();  // Commentted this line out
                    String lsStrDocId = cmd1.StandardOutput.ReadToEnd().ToString();
                    System.IO.File.WriteAllText(lsStrConsoleAppLog, lsStrDocId);
                }
                catch (Exception ex)
                {
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Oops. It was caught inside CONSOLEAPP1 with:", "\n");
                    lsStrMessage = String.Concat(lsStrMessage, ex.ToString());
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "CMDORPHANED")  //Call ConsoleApp1
            {
                // Changes needed
                // Write log entry to c:\programdata\titus\Content.Extensibility.log instead of C:\test.
                if (lsStrSoftwareRunning == "Content.Extensibility.dll")
                {
                    //jjjjjjj
                    // Command line to run
                    // C:\Program Files (x86)\Seclore\FileSecure\Desktop Client\SecloreActionDispatcher.exe -ActionId "protect" -ApplicationName "TITUS" -File "C:\temp\Seclore - TCD.docx" -Type "self" -Classification "3"
                    string lsStrArguments = "";
                    lsStrArguments = string.Concat(lsStrArguments, @" /c start ", "ConsoleApp1.exe", " ");      // What to call
                    lsStrArguments = string.Concat(lsStrArguments, " ", lsStrFunction.ToUpper(), " ");          // Has to match the CMD orphaned process to end up here again when called by 
                                                                                                                //                                             
                                                                                                                //    lsStrParameter1         
                                                                                                                //    workingdirCE txt    Working directory for ConsoleApp1.exe, i.e. where Content.Extensibility is stored
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter2, " ");  //    sleep        int    sleep interval in milliseconds
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter3, " ");  //    workingdirOP txt    Working directory to run the orphaned process from
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter4, " ");  //    filename     txt    Name of full file name (or as much as desired executeable to call
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter5, " ");  //    parameter1   txt    Parameter 1 value for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter6, " ");  //    parameter2   txt    Parameter 2 value for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter7, " ");  //    parameter3   txt    Parameter 3 value for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter8, " ");  //    parameter4   txt    Parameter 4 value for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter9, " ");  //    parameter5   txt    Parameter 5 value for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter10, " "); //    parameter6   txt    Parameter 6 value for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter11, " "); //    parameter7   txt    Parameter 7 value for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter12, " "); //    parameter8   txt    Parameter 8 value for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter13, " "); //    parameter9   txt    Parameter 9 value for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter14, " "); //    parameter10  txt    Parameter 10 value for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter15);      //    parameter11  txt    Parameter 11 value for executeable


                    //System.IO.File.WriteAllText(@"C:\test\CECMDORPHANED.txt", String.Concat(lsStrSoftwareRunning, " ", lsStrArguments));

                    Console.WriteLine("lsStrArguments  = \n {0}", lsStrArguments);


                    //String lsStrConsoleAppLog = @"C:\users\public\ConsoleApp1.log";
                    //cmdsi.RedirectStandardOutput = true; // added xx



                    String command = lsStrArguments;

                    ProcessStartInfo cmdsi = new ProcessStartInfo("cmd.exe");
                    cmdsi.Arguments = command;
                    cmdsi.UseShellExecute = true; // added xx
                    cmdsi.WorkingDirectory = lsStrParameter1; //    workingdirCE txt    Working directory for ConsoleApp1.exe, i.e. where Content.Extensibility is stored
                    //System.IO.File.WriteAllText(@"C:\test\CECMDORPHANEDWorkingDir.txt", String.Concat("cmdsi.WorkingDirectory = ", cmdsi.WorkingDirectory));
                    Process cmd1 = Process.Start(cmdsi);
                    cmd1.WaitForExit(1);  // Commentted this line out

                    //String lsStrDocId = cmd1.StandardOutput.ReadToEnd().ToString();
                    //System.IO.File.WriteAllText(lsStrConsoleAppLog, lsStrDocId);
                }
                if (lsStrSoftwareRunning == "ConsoleApp1.exe")
                {

                    Thread.Sleep(Int32.Parse(lsStrParameter1));                           // sleep

                    string lsStrArguments = "";
                    lsStrArguments = string.Concat(lsStrArguments, @" /c start ", lsStrParameter2, " ");      // What to call or executeable
                                                                                                              // lsStrArguments = string.Concat(lsStrArguments, @" start ", lsStrParameter2, " ");      
                                                                                                              // What to call
                                                                                                              // lsStrArguments = string.Concat(lsStrArguments, " ", lsStrFunction.ToUpper(), " ");                   
                                                                                                              // Has to match the CMD orphaned process to end up here again when called by 
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter4, " ");  //    parameter1  txt for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter5, " ");  //    parameter2  txt for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter6, " ");  //    parameter3  txt for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter7, " ");  //    parameter4  txt for executeable

                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter8, " ");  //    parameter5  txt for executeable
                    lsStrParameter9 = string.Concat("\"", lsStrParameter9, "\"");
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter9, " ");  //    parameter6  txt for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter10, " "); //    parameter7  txt for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter11, " "); //    parameter8  txt for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter12, " "); //    parameter9  txt for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter13, " "); //    parameter10 txt for executeable
                    lsStrArguments = string.Concat(lsStrArguments, lsStrParameter14);      //    parameter11 txt for executeable

                    lsStrArguments = lsStrArguments + @" >c:\test\ocr_results";

                    //System.IO.File.WriteAllText(@"C:\test\CACMDORPHANED.txt", String.Concat(lsStrSoftwareRunning, " *** ", lsStrArguments));

                    // From https://stackoverflow.com/questions/1469764/run-command-prompt-commands

                    // System.Diagnostics.Process process = new System.Diagnostics.Process();
                    // System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
                    // startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                    // startInfo.FileName = "cmd.exe";
                    // startInfo.Arguments = "/C copy /b Image1.jpg + Archive.rar Image2.jpg";
                    // process.StartInfo = startInfo;
                    // process.Start();
                    // 
                    // START:::::: Working as needed but hard coded...
                    //System.Diagnostics.Process process = new System.Diagnostics.Process();
                    //System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
                    //startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                    //startInfo.FileName = "cmd.exe";
                    //startInfo.WorkingDirectory = @"C:\Users\bob\Downloads\Content.Extensibility\ConsoleApp1\ConsoleApp1\bin\Debug";
                    //startInfo.Arguments = @"/C ConsoleApp1.exe OCR C:\Users\bob\Downloads\Content.Extensibility\ConsoleApp1\ConsoleApp1\bin\Debug\VISA.jpg -SILENT >OCR_OUTPUT.txt";
                    //process.StartInfo = startInfo;
                    //process.Start();
                    // END:::::: Working as needed but hard coded...

                    // START:::::: Working as needed but hard coded...
                    //System.Diagnostics.Process process = new System.Diagnostics.Process();
                    //System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
                    //startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                    //startInfo.FileName = "cmd.exe";
                    //startInfo.WorkingDirectory = lsStrParameter3;                                                           // @"C:\Users\bob\Downloads\Content.Extensibility\ConsoleApp1\ConsoleApp1\bin\Debug";
                    //startInfo.Arguments = lsStrArguments;                                                                   // @"/C ConsoleApp1.exe OCR C:\Users\bob\Downloads\Content.Extensibility\ConsoleApp1\ConsoleApp1\bin\Debug\VISA.jpg -SILENT >OCR_OUTPUT.txt";
                    //process.StartInfo = startInfo;
                    //process.Start();

                    // END:::::: Working as needed but hard coded...

                    // ************************* START ORIGINAL ************************************
                    // startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                    Console.WriteLine(lsStrArguments);
                    Console.WriteLine(lsStrParameter4);
                    ProcessStartInfo cmdsi = new ProcessStartInfo("cmd.exe");
                    cmdsi.WorkingDirectory = lsStrParameter3; // working directory
                    cmdsi.Arguments = lsStrArguments;
                    Process cmd1 = Process.Start(cmdsi);
                    //cmdsi.UseShellExecute = true; // added xx
                    //                       
                    //cmd1.WaitForExit(1);  // Commentted this line out
                    // ************************* STOP ORIGINAL ************************************
                }
                try
                {

                }
                catch (Exception ex)
                {
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Oops. It was caught inside CONSOLEAPP1 with:", "\n");
                    lsStrMessage = String.Concat(lsStrMessage, ex.ToString());
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "COPYFILE")
            {
                if (lsStrExtendedLoggingEnabled == "1")
                {
                    //Log.Debug(lsStrConfigObject, " ", "lsStrFunction = {0}", lsStrFunction);
                    //Log.Debug(lsStrConfigObject, " ", "lsStrParameter1 = {0}", lsStrParameter1);
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Extended logging enabled.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrFunction = ", lsStrFunction);
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrParameter1 = ", lsStrParameter1);
                }
                try
                {
                    File.Copy(lsStrParameter1, lsStrParameter2, false);
                }
                catch (Exception ex)
                {
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Looks like the ", lsStrFunction.ToUpper(), " function had an exception.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", ex);
                    //Log.Error(ex, "Exception is {0}");
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "CPCT")  // Convert to Percentage
            {
                try
                {
                    //lsStrMessage = String.Concat(lsStrMessage, "\n", "Inside CPCT");
                    float lsVarPercentage = float.Parse(lsStrParameter1) * 100;
                    //lsStrMessage = String.Concat(lsStrMessage, "\n", "Inside CPCT lsVarPercentage = ", lsVarPercentage.ToString());
                    lsStrResult = lsVarPercentage.ToString();
                    //lsStrMessage = String.Concat(lsStrMessage, "\n", "Inside CPCT lsStrResult = ", lsStrResult);
                    int lsIntLocationOfDecimal = TextTool.GetNthIndexOfChar(lsStrResult, '.', 1);
                    //lsStrMessage = String.Concat(lsStrMessage, "\n", "Inside CPCT lsIntLocationOfDecimal = ", lsIntLocationOfDecimal.ToString());
                    //lsStrMessage = String.Concat(lsStrMessage, "\n", "Inside CPCT lsStrParameter2 = ", lsStrParameter2);
                    //lsStrMessage = String.Concat(lsStrMessage, "\n", "Inside CPCT lsStrParameter2.Length = ", lsStrParameter2.Length);
                    if (lsStrParameter2.Length == 0)
                    {
                        lsStrResult = lsStrResult.Substring(0, lsIntLocationOfDecimal);
                    }
                    else
                    {
                        int lsIntMaxLengthOfResult = lsIntLocationOfDecimal + Int32.Parse(lsStrParameter2);
                        // lsStrMessage = String.Concat(lsStrMessage, "\n", "Inside CPCT else");
                        // lsStrMessage = String.Concat("lsIntLocationOfDecimal + Int32.Parse(lsStrParameter2) = ", (lsIntLocationOfDecimal + Int32.Parse(lsStrParameter2)).ToString());
                        // lsStrMessage = String.Concat(lsStrMessage, "\n", "lsIntMaxLengthOfResult = ", lsIntMaxLengthOfResult.ToString());
                        // lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrParameter2 = ", lsStrParameter2);
                        // lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrResult.Length = ", lsStrResult.Length);
                        // lsStrMessage = String.Concat(lsStrMessage, "\n", "lsIntLocationOfDecimal = ", lsIntLocationOfDecimal.ToString());

                        if (lsIntMaxLengthOfResult > lsStrResult.Length)
                        {
                            lsIntMaxLengthOfResult = lsStrResult.Length;
                            lsStrMessage = String.Concat(lsStrMessage, "\n", "The total length was truncated, not rounded to ", lsIntMaxLengthOfResult.ToString(), " characters.");
                            if (lsStrLoggingEnabled.ToUpper() == "TRUE")  // Is Logging enabled?
                            {
                                //Log.Debug("The total length was truncated, not rounded to {0}", lsIntMaxLengthOfResult.ToString());
                            }
                        }
                        lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrResult = ", lsStrResult);
                        lsStrResult = lsStrResult.Substring(0, lsIntMaxLengthOfResult);
                    }
                    lsStrResult = String.Concat(lsStrResult, "%");
                }
                catch (Exception ex)
                {
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Oops. It was caught inside CPCT with:", "\n");
                    lsStrMessage = String.Concat(lsStrMessage, ex.ToString());
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "DELETEFILE")
            {
                if (lsStrExtendedLoggingEnabled == "1")
                {
                    //Log.Debug(lsStrConfigObject, " ", "lsStrFunction = {0}", lsStrFunction);
                    //Log.Debug(lsStrConfigObject, " ", "lsStrParameter1 = {0}", lsStrParameter1);
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Extended logging enabled.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrFunction = ", lsStrFunction);
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrParameter1 = ", lsStrParameter1);
                }
                try
                {
                    File.Delete(lsStrParameter1);
                }
                catch (Exception ex)
                {
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Looks like the ", lsStrFunction.ToUpper(), " function had an exception.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", ex);
                    //Log.Error(ex, "Exception is {0}");
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "DEMO")
            {
                lsStrResult = "Some demo text to test with";
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "DIVIDEBYZERO")
            {
                // https://github.com/serilog/serilog/wiki/Getting-Started
                lsStrResult = "Divide by zero error.";
                int a = 10, b = 0;
                try
                {
                    //Log.Debug("lsStrFunction.ToUpper() {0}", "DIVIDEBYZERO");
                    //Log.Debug("Dividing {A} by {B}", a, b);
                    Console.WriteLine(a / b);
                }
                catch (Exception ex)
                {
                    //Log.Error("Intentional DIVIDEBYZERO error. {0}", ex);
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Intentional DIVIDEBYZERO error. The following exception was expected");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", ex.ToString());
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "If ", lsStrSoftwareRunning, " had made an exception, it would look something like above.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", @"such errors are also written by Serilog to C:\ProgramData\TITUS\CustomResources\Content.Extensibility\Content.Extensibility.YYYYMMDD.log");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "where YYYY = " + DateTime.Today.ToString("yyyy") + " year when error occurred");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "where MM   = " + DateTime.Today.ToString("MM") + "   month when error occurred");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "where DD   = " + DateTime.Today.ToString("dd") + "   day when error occurred");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", @"i.e. For today, " + DateTime.Today.ToString("d") +
                        @", it would be written to C:\ProgramData\TITUS\CustomResources\Content.Extensibility\Content.Extensibility." +
                        DateTime.Today.ToString("yyyy") + DateTime.Today.ToString("MM") + DateTime.Today.ToString("dd") + ".log");
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "ENVVAR")
            {
                if (lsStrExtendedLoggingEnabled == "1")
                {
                    //Log.Debug(lsStrConfigObject, " ", "lsStrFunction = {0}", lsStrFunction);
                    //Log.Debug(lsStrConfigObject, " ", "lsStrParameter1 = {0}", lsStrParameter1);
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Extended logging enabled.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrFunction = ", lsStrFunction);
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrParameter1 = ", lsStrParameter1);
                }
                try
                {
                    lsStrResult = Environment.GetEnvironmentVariable(lsStrParameter1);
                }
                catch (Exception ex)
                {
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Looks like the ", lsStrFunction.ToUpper(), " function had an exception.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", ex);
                    //Log.Error(ex, "Exception is {0}");
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "FILEINFO.LENGTH")
            {
                var sourceFile = new FileInfo(lsStrParameter1);
                lsStrResult = sourceFile.Length.ToString();
                if (lsStrParameter2 == "*")
                {
                    lsStrResult = String.Concat(
                    "Attributes.Archive:          ", sourceFile.Attributes.HasFlag(FileAttributes.Archive), "\n",
                    "Attributes.Compressed:       ", sourceFile.Attributes.HasFlag(FileAttributes.Compressed), "\n",
                    "Attributes.Device:           ", sourceFile.Attributes.HasFlag(FileAttributes.Device), "\n",
                    "Attributes.Directory:        ", sourceFile.Attributes.HasFlag(FileAttributes.Directory), "\n",
                    "Attributes.Encrypted:        ", sourceFile.Attributes.HasFlag(FileAttributes.Encrypted), "\n",
                    "Attributes.Hidden:           ", sourceFile.Attributes.HasFlag(FileAttributes.Hidden), "\n",
                    "Attributes.IntegrityStream:  ", sourceFile.Attributes.HasFlag(FileAttributes.IntegrityStream), "\n",
                    "Attributes.Normal:           ", sourceFile.Attributes.HasFlag(FileAttributes.Normal), "\n",
                    "Attributes.NoScrubData:      ", sourceFile.Attributes.HasFlag(FileAttributes.NoScrubData), "\n",
                    "Attributes.Offline:          ", sourceFile.Attributes.HasFlag(FileAttributes.Offline), "\n",
                    "Attributes.ReadOnly:         ", sourceFile.Attributes.HasFlag(FileAttributes.ReadOnly), "\n",
                    "Attributes.ReparsePoint:     ", sourceFile.Attributes.HasFlag(FileAttributes.ReparsePoint), "\n",
                    "Attributes.System:           ", sourceFile.Attributes.HasFlag(FileAttributes.System), "\n",
                    "Attributes.Temporary:        ", sourceFile.Attributes.HasFlag(FileAttributes.Temporary), "\n",
                    "Attributes.Encrypted:        ", sourceFile.Attributes.HasFlag(FileAttributes.Encrypted), "\n",
                    "sourceFile.CreationTime:     ", sourceFile.CreationTime, "\n",
                    "sourceFile.CreationTimeUtc:  ", sourceFile.CreationTimeUtc, "\n",
                    "sourceFile.Directory:        ", sourceFile.Directory, "\n",
                    "sourceFile.DirectoryName:    ", sourceFile.DirectoryName, "\n",
                    "sourceFile.Exists:           ", sourceFile.Exists, "\n",
                    "sourceFile.Extension:        ", sourceFile.Extension, "\n",
                    "sourceFile.FullName:         ", sourceFile.FullName, "\n",
                    "sourceFile.IsReadOnly:       ", sourceFile.IsReadOnly, "\n",
                    "sourceFile.LastAccessTime:   ", sourceFile.LastAccessTime, "\n",
                    "sourceFile.LastAccessTimeUtc:", sourceFile.LastAccessTimeUtc, "\n",
                    "sourceFile.LastWriteTime:    ", sourceFile.LastWriteTime, "\n",
                    "sourceFile.LastWriteTime:    ", sourceFile.LastWriteTime, "\n",
                    "sourceFile.Length:           ", sourceFile.Length, "\n",
                    "sourceFile.Name:             ", sourceFile.Name
                    );
                }
                else
                {
                    string[] words = lsStrParameter1.Split(',');

                    string text = "";
                    foreach (var word in words)
                    {
                        if (text == "Something")
                        {
                            lsStrResult = "This function, fileinfo is Not finished yet.";
                        }
                    }
                }






                //string sourceFile_Name = sourceFile.Name;
                //string sourceFile_Name.Replace(".doc", "");
                //string clockTicks = DateTime.Now.Ticks.ToString();
                //newFileName = String.Concat(clockTicks, ".temp.", newFileName);
                //Console.WriteLine(newFileName);

                //Microsoft.Office.Interop.Word.Application word = new Microsoft.Office.Interop.Word.Application();
                //var document = word.Documents.Open(lsStrParameter1);
                //word.DisplayAlerts = WdAlertLevel.wdAlertsNone;
                //document.SaveAs2(newFileName, WdSaveFormat.wdFormatXMLDocument,
                //                 CompatibilityMode: WdCompatibilityMode.wdWord2010);
                //document.Saved = true;

                //word.ActiveDocument.Close();
                //word.Quit();

                //File.Delete(lsStrParameter1);
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "FNDC" || lsStrFunction.ToUpper() == "FIND" || lsStrFunction.ToUpper() == "GNIC") // FNDC and FIND are deprecated but these need to stay for reliability
            {

                try
                {
                    Char lsChrParamter2 = lsStrParameter2[0];
                    int lsIntCharIndex;
                    lsIntCharIndex = TextTool.GetNthIndexOfChar(lsStrParameter1, lsChrParamter2, Int32.Parse(lsStrParameter3));
                    if (lsIntCharIndex > -1)
                    {
                        lsIntCharIndex++;
                    }
                    lsStrResult = lsIntCharIndex.ToString();
                }
                catch (Exception ex)
                {
                    //Log.Error(ex, "GNIC didn't work.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "GNIC didn't work.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", ex.ToString());
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "FWDM") // File Write Date Modified
            {

                //lsStrParameter1 = @"C:\Users\bill.brunt\source\repos\billbrunt\ConsoleApp1\ConsoleApp1\bin\Debug\TestFWDM.txt";
                //lsStrParameter2 = "2019-09-29 18:18:21Z";
                // lsStrMessage

                try
                {
                    // Console.WriteLine("The current date/time is: {0}", DateTime.Now);
                    // Thread.Sleep(5000);
                    // Console.WriteLine("The current date/time is: {0}", DateTime.Now);
                    // File whose classification is being changed.

                    DateTime lsDteLocalTime = DateTime.ParseExact(lsStrParameter2.Substring(0, 19), "yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture).ToLocalTime();
                    string iString = lsStrParameter2; //"2005-05-05 22:12:00 PM";
                    DateTime oDate = DateTime.ParseExact(iString, "yyyy-MM-dd HH:mm:ss tt", null);


                    File.SetLastWriteTime(lsStrParameter1, oDate);
                    // need to call ConsoleApp1 as asynchronous process that sleeps and then acts
                    // Since the TCD policy event change classification first runs a the custom condition and then
                    // write the metadata as determined by testing, it necessary to let the policy finish
                    // and then change the date. This is done by spawning an asynchronous process which does not have a parent
                    // having it go to sleep and then changing the date modified back to what it was originally. The value in parameter2.

                    //if (lsStrSoftwareRunning == "Content.Extensibility")
                    //{
                    //    //// Call the ConsoleApp1 asynchronously.
                    //    //https://stackoverflow.com/questions/8434379/start-new-process-without-being-a-child-of-the-spawning-process

                    //    //    System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo();
                    //    //    psi.FileName = @"cmd";
                    //    //    psi.Arguments = "/C start notepad.exe";
                    //    //    psi.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                    //    //    System.Diagnostics.Process.Start(psi);


                    //}
                    //// Canary file for Content.Extensibility, i.e. the CE in Cx.

                    //if (lsStrParameter3 != "" && lsStrSoftwareRunning == "Content.Extensibility")
                    //{
                    //    string lsStrPath = lsStrParameter3;
                    //    DateTime lsDteDateModifiedCx;
                    //    if (lsStrParameter4 != "")
                    //    {
                    //        lsDteDateModifiedCx = DateTime.ParseExact(lsStrParameter4.Substring(0, 19), "yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture).ToLocalTime();
                    //    }
                    //    else
                    //    {
                    //        lsDteDateModifiedCx = DateTime.Now;
                    //    }
                    //    File.SetLastWriteTime(lsStrPath, lsDteDateModifiedCx);
                    //}

                    //// Canary file for ConsoleApp1, i.e. the CE in Cx.

                    //if (lsStrParameter5 != "" && lsStrSoftwareRunning == "ConsoleApp1.exe")
                    //{
                    //    string lsStrPath = lsStrParameter3;
                    //    DateTime lsDteDateModifiedCx;
                    //    if (lsStrParameter6 != "")
                    //    {
                    //        lsDteDateModifiedCx = DateTime.ParseExact(lsStrParameter6.Substring(0, 19), "yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture).ToLocalTime();
                    //    }
                    //    else
                    //    {
                    //        lsDteDateModifiedCx = DateTime.Now;
                    //    }
                    //    File.SetLastWriteTime(lsStrPath, lsDteDateModifiedCx);
                    //}

                    //// lsStrSoftwareRunning = ""


                    //lsStrMessage = "FWDM End of Try with no catch run or catch me if you can.";

                }
                catch (Exception ex)
                {
                    //Log.Error("FWDM error. {0}", ex);
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "FWDM or File Write Date Modified error has occurred.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", ex.ToString());
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Check the format the of date modifed being passed by Titus policy engine from property.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "File.ModifiedTimeUtc is yyyy-MM-dd HH:mm:ssZ");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "For example, the 2:18:21 PM in EST time zone on Sept 29 2019 is represented as");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "2019-09-29 02:18:21 PM");
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "GETPREOPCOFFICETEXT") // GetPreOPCofficeText
            {
                //var newFile = new FileInfo(lsStrParameter1);
                //string newFileName = String.Concat(newFile.DirectoryName, @"\", newFile.Name.Replace(".doc", "."), DateTime.Now.Ticks.ToString(), newFile.Extension);
                //// Console.WriteLine("newFileName = {0}",newFileName);
                //Microsoft.Office.Interop.Word.Application oWord = new Microsoft.Office.Interop.Word.Application();
                //// Console.WriteLine("after new Word Application");
                //oWord.DisplayAlerts = WdAlertLevel.wdAlertsNone;
                //// Console.WriteLine("after WdAlertLevel.wdAlertsNone");
                //var oDoc = oWord.Documents.Open(lsStrParameter1);
                //// Console.WriteLine("after new Word open");
                //// oDoc.SaveAs2(newFileName, WdSaveFormat.wdFormatXMLDocument,
                //// CompatibilityMode: WdCompatibilityMode.wdWord2010);
                //oDoc.Saved = true;
                //oWord.Selection.Document.Content.Select();
                //lsStrResult = oWord.Selection.Text;
                //oWord.ActiveDocument.Close();
                //oWord.Quit();
                ////File.Delete(lsStrParameter1);
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "GETAPPSETTING")
            {

                #region Error check   2 Read from App.config
                try
                {

                    string strConfigFile;

                    if (lsStrParameter2 != "")
                    {
                        strConfigPath = String.Concat(lsStrParameter2, @"\");
                    }
                    else
                    {
                        if (lsStrSoftwareRunning != "Content.Extensibility.dll")
                        {
                            strConfigPath = @"C:\Program Files\Titus\TITUS Illuminate\CustomFunctions\Content.Extensibility\";
                        }
                    }

                    if (lsStrParameter3 != "")
                    {
                        strConfigFile = lsStrParameter3;
                    }
                    if (lsStrSoftwareRunning == "ConsoleApp1.exe")
                    {
                        strConfigFile = "ConsoleApp1.exe.config";
                        string strPathFile = String.Concat(strConfigPath, strConfigFile);
                        Configuration config = null;
                        config = ConfigurationManager.OpenExeConfiguration(strPathFile);

                        AppSettingsSection appSettings = config.AppSettings as AppSettingsSection;
                        //System.IO.File.WriteAllText(@"c:\temp5\GetAppSetting00.txt", String.Concat("strPathFile = ", strPathFile));
                        //System.IO.File.WriteAllText(@"c:\temp5\GetAppSetting01.txt", String.Concat("lsStrParameter1 = ", lsStrParameter1));
                        lsStrResult = ConfigurationManager.AppSettings[lsStrParameter1];
                        //System.IO.File.WriteAllText(@"c:\temp5\GetAppSetting02.txt", String.Concat("lsStrResult = ", lsStrResult));
                    }
                    if (lsStrSoftwareRunning == "Content.Extensibility.dll")
                    {
                        // strConfigPath = String.Concat(strConfigPath, ".config");
                        Configuration config;
                        //System.IO.File.WriteAllText(@"c:\temp5\GetAppSetting04.txt", String.Concat("strConfigPath = ", strConfigPath));
                        //System.IO.File.WriteAllText(@"c:\temp5\GetAppSetting05.txt", String.Concat("lsStrParameter1 = ", lsStrParameter1));
                        //System.IO.File.WriteAllText(@"c:\temp5\GetAppSetting06.txt", String.Concat("lsStrFunction.ToUpper() = ", lsStrFunction.ToUpper()));
                        config = ConfigurationManager.OpenExeConfiguration(strConfigPath);
                        lsStrResult = GetAppSetting(config, lsStrParameter1);
                    }
                }
                catch (System.Exception ex)
                {
                    //System.IO.File.WriteAllText(@"c:\temp5\GetAppSettingError01.txt", String.Concat("ex.ToString() = ", ex.ToString()));
                    lsStrMessage = String.Concat("Catch (Exception ex) occurred with Function:", lsStrFunction.ToUpper());
                    lsStrMessage = String.Concat(lsStrMessage, "\n", ex.ToString());

                }
                #endregion
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "GLWT")  // Get Last Write Time or what File Explorer shows as "Date modified"
            {

                try
                {
                    DateTime lsDteDateModified;
                    lsDteDateModified = File.GetLastWriteTime(lsStrParameter1);

                    lsStrResult = lsDteDateModified.ToString("yyyy-MM-dd HH:mm:ss tt");
                }
                catch (Exception ex)
                {

                    lsStrMessage = String.Concat(lsStrMessage, "\n", "GTLW didn't work.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", ex.ToString());
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "SLWT") // Set Last Write Time             
            {
                try
                {
                    String lsStrTextToWriteOut = string.Concat("The current date/time is ", DateTime.Now.ToString());
                    //
                    Thread.Sleep(2000);
                    lsStrTextToWriteOut = string.Concat(lsStrTextToWriteOut, "\n", "The current date/time is ", DateTime.Now.ToString());
                    lsStrResult = "FWDMTEST was run.";
                    //String lsStrConsoleAppLog = @"C:\users\public\FWDMTEST.log";
                    //System.IO.File.WriteAllText(lsStrConsoleAppLog, lsStrTextToWriteOut);
                    // File.GetLastWriteTime()
                    File.SetLastWriteTime(@"C:\Users\bob\Downloads\TCDPreserveDateModified\test.docx", DateTime.ParseExact("2019-09-29 18:18:21", "yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture).ToLocalTime());
                }
                catch (Exception ex)
                {
                    //Log.Error("FWDMTEST error. {0}", ex);
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "FWDM or File Write Date Modified error has occurred.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", ex.ToString());
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Check the format the of date modifed being passed by Titus policy engine from property.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "File.ModifiedTimeUtc is yyyy-MM-dd HH:mm:ssZ");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "For example, the 2:18pm in EST time zone on Sept 29 2019 is represented as");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "2019-09-29 18:18:21Z");
                }

                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "GUID")
            {
                //if (lsStrExtendedLoggingEnabled == "1")
                //{
                //    Log.Debug(lsStrConfigObject, " ", "lsStrFunction = {0}", lsStrFunction);
                //    Log.Debug(lsStrConfigObject, " ", "lsStrParameter1 = {0}", lsStrParameter1);
                //    lsStrMessage = String.Concat(lsStrMessage, "\n", "Extended logging enabled.");
                //    lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrFunction = ", lsStrFunction);
                //    lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrParameter1 = ", lsStrParameter1);
                //}
                //try
                //{
                //    lsStrResult = Guid.NewGuid().ToString();
                //}
                //catch (Exception ex)
                //{
                //    lsStrMessage = String.Concat(lsStrMessage, "\n", "Looks like the ", lsStrFunction.ToUpper(), " function had an exception.");
                //    lsStrMessage = String.Concat(lsStrMessage, "\n", ex);
                //    Log.Error(ex, "Exception is {0}");
                //}
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "HELP")
            {
                if (lsStrParameter1 == "" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "For deployment help, type", "\n");
                    lsStrResult = String.Concat(lsStrResult, "HELP DEPLOYMENT", "\n\n");
                    lsStrResult = String.Concat(lsStrResult, "The following functions are available.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "+.....................................: Adds num1 + num2 + num3 + ...", "\n");
                    lsStrResult = String.Concat(lsStrResult, "-.....................................: Subtracts num2, num3, ... from num1.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "*.....................................: Multiples num1 by num2 by num3 ...", "\n");
                    lsStrResult = String.Concat(lsStrResult, "/.....................................: Divides num1 by num2.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "ASC...................................: Returns the ASCII value of each character in text.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "CPCT..................................: Multiplies by 100 and appends %.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "DIVDEBYZERO...........................: Intentional divide by zero to show logging.", "\n");
                    //              lsStrResult = String.Concat(lsStrResult, "FILE..................................: Reads the function and parameters from a file.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "FIRSTLEVEL............................: A type of parameter which takes the place of and shifts other parameters over", "\n");
                    lsStrResult = String.Concat(lsStrResult, "GNIC..................................: Gets nth index of character in text.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "LEN...................................: Returns the length.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "LINE..................................: Returns specific line number.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "MID...................................: Performs as MID in Excel", "\n");
                    // NthIndexOf(this string target, string value, int n)
                    lsStrResult = String.Concat(lsStrResult, "NI....................................: NI returns the nth index of txt2 within text.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "RPAD..................................: Adds padding characters on the right side of text.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "RTRIM.................................: Removes all spaces on the right side of text.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "UPPER.................................: Converts a text string to all uppercase letters.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "To get help on a function, type HELP and then type the function name, i.e.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "HELP MID", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "To get all help, use", "\n");
                    lsStrResult = String.Concat(lsStrResult, "HELP ALL", "\n\n");
                    lsStrResult = String.Concat(lsStrResult, "For development help, type", "\n");
                    lsStrResult = String.Concat(lsStrResult, "HELP DEVELOPMENT", "\n\n");

                    if (lsStrLoggingEnabled.ToUpper() == "TRUE")  // Is Logging enabled?
                    {
                        //Log.Debug("Completed HELP function.");
                    }
                    lsBolValidFunction = true;
                }
                if (lsStrParameter1.ToUpper() == "+" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "+ num1 num2 num3 ...", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "log             [boolean]   LOG or NOLOG to control writing to the log or not for performance.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function        +           Adds num1 + num2 + num3 + ...", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 1     num1        first number to add.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 2     num2        second number to add.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 3     num3        third number to add.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 4     num4        fourth number to add.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 5     num5        fifth number to add.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 6     num6        six number to add.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 7     num7        seventh number to add.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 8     num8        eiight number to add.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 9     num9        ninth number to add.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 10    num10       tenth number to add.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "\n", "Example results....");
                    lsStrResult = String.Concat(lsStrResult, "\n", @"                     ConsoleApp1.exe LOG +-1123E+16 a 781.121E+17");
                    lsStrResult = String.Concat(lsStrResult, "\n");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                     Above is the result.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                     Logging Enabled = TRUE");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                     Logging Enabled = TRUE");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                     Extended Logging Enabled = 0");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                     Message = The + function errored. Check that all your ParametersN are valid numbers and format.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                     ReturnCode = 2");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                     Runtime = 87.515625");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                     Version = " + lsStrVersionNo);
                    lsStrResult = String.Concat(lsStrResult, "\n");
                    lsStrResult = String.Concat(lsStrResult, "\n", @"                     ConsoleApp1.exe LOG + -1123E+16 781.121E+17");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                     6.68821E+19");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                     Above is the result.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                     Logging Enabled = TRUE");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                     Extended Logging Enabled = 0");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                     Message = Status is all good.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                     ReturnCode = 0");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                     Runtime = 67.9296875");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                     Version = " + lsStrVersionNo);
                    lsStrResult = String.Concat(lsStrResult, "\n", "End of Example results....\n");
                    lsBolValidFunction = true;

                }
                if (lsStrParameter1.ToUpper() == "-" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "- num1 num2 num3...", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "log             [boolean]   LOG or NOLOG to control writing to the log or not for performance.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function        -           subtracts num2 num3... from num1", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 1     num1        all other numbers subtract from this num1.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 2     num2        second number subtracted from num1.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 3     num3        third number subtracted from num1.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 4     num4        fourth number subtracted from num1.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 5     num5        fifth number subtracted from num1.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 6     num6        six number subtracted from num1.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 7     num7        seventh number subtracted from num1.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 8     num8        eiight number subtracted from num1.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 9     num9        ninth number subtracted from num1.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 10    num10       tenth number subtracted from num1.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "\n", "Example results....");
                    lsStrResult = String.Concat(lsStrResult, "\n", @"                      ConsoleApp1.exe LOG +-1123E+16 a 781.121E+17");
                    lsStrResult = String.Concat(lsStrResult, "\n", " ");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Above is the result.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Logging Enabled = TRUE");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Extended Logging Enabled = 0");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Message = The - function errored. Check that all your ParametersN are valid numbers and format.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      ReturnCode = 2");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Runtime = 62.859375");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Version = " + lsStrVersionNo);
                    lsStrResult = String.Concat(lsStrResult, "\n");
                    lsStrResult = String.Concat(lsStrResult, "\n", @"                      ConsoleApp1.exe LOG - -1123E+16 781.121E+17");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      -8.93421E+19");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Above is the result.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Logging Enabled          = TRUE");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Extended Logging Enabled = 0");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Message                  = Status is all good.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      ReturnCode               = 0");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Runtime                  = 67.8125");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Version                  = " + lsStrVersionNo);
                    lsStrResult = String.Concat(lsStrResult, "\n", "End of Example results....\n");
                    lsBolValidFunction = true;
                }
                if (lsStrParameter1.ToUpper() == "*" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "* num1 num2 num3...", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "log             [boolean]   LOG or NOLOG to control writing to the log or not for performance.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function        *           Multiples num1 by num2 by num3 ...", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 1     num1        is multiplied with num1 cummulatively.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 2     num2        is multiplied with num1 cummulatively.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 3     num3        is multiplied with num1 cummulatively.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 4     num4        is multiplied with num1 cummulatively.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 5     num5        is multiplied with num1 cummulatively.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 6     num6        is multiplied with num1 cummulatively.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 7     num7        is multiplied with num1 cummulatively.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 8     num8        is multiplied with num1 cummulatively.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 9     num9        is multiplied with num1 cummulatively.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 10    num10       is multiplied with num1 cummulatively.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "\n", "Example results....");
                    lsStrResult = String.Concat(lsStrResult, "\n", @"                      ConsoleApp1 * 1 0.5 2");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      1");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Above is the result.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Logging Enabled          = NULL");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Extended Logging Enabled = 0");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Message                  = Status is all good.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      ReturnCode               = 0");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Runtime                  = 16.328125");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Version                  = " + lsStrVersionNo);
                    lsStrResult = String.Concat(lsStrResult, "\n");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      ConsoleApp1 * 1 0.5 2 a");
                    lsStrResult = String.Concat(lsStrResult, "\n");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Above is the result.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Logging Enabled          = NULL");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Extended Logging Enabled = 0");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Message                  = The * function errored. Check that all your ParametersN are valid numbers and format.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      ReturnCode               = 2");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Runtime                  = 17.1015625");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Version                  = " + lsStrVersionNo);
                    lsStrResult = String.Concat(lsStrResult, "\n", "End of Example results....\n");
                    lsBolValidFunction = true;

                }
                if (lsStrParameter1.ToUpper() == @"/" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "/ num1 num2 num3... ", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "log             [boolean]   LOG or NOLOG to control writing to the log or not for performance.", "\n");
                    lsStrResult = String.Concat(lsStrResult, @"Function        /           Divides num1 by num2 by num3...", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 1     num1        Numerator.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 2     num2        Denominator.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 3     num3        Denominator.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 4     num4        Denominator.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 5     num5        Denominator.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 6     num6        Denominator.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 7     num7        Denominator.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 8     num8        Denominator.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 9     num9        Denominator.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 10    num10       Denominator.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "\n", "Example results....");
                    lsStrResult = String.Concat(lsStrResult, "\n", @"                      ConsoleApp1 / 1 0.5 2");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      1");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Above is the result.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Logging Enabled          = NULL");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Extended Logging Enabled = 0");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Message                  = Status is all good.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      ReturnCode               = 0");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Runtime                  = 25.171875");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Version                  = " + lsStrVersionNo);
                    lsStrResult = String.Concat(lsStrResult, "\n", "                                              ");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      ConsoleApp1 / 1 0.5 2 *");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                                              ");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Above is the result.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Logging Enabled          = NULL");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Extended Logging Enabled = 0");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Message                  = The / function errored. Check that all your ParametersN are valid numbers and format.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      ReturnCode               = 2");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Runtime                  = 23.078125");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Version                  = " + lsStrVersionNo);
                    lsStrResult = String.Concat(lsStrResult, "\n", "End of Example results....\n");
                    lsBolValidFunction = true;
                }
                if (lsStrParameter1.ToUpper() == "ASC" || lsStrParameter1.ToUpper() == "ALL") // Tested
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "ASC text", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "log             [boolean]   LOG or NOLOG to control writing to the log or not for performance.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function        ASC         Returns the ASCII value of each character in text.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 1     text        is the text string you want ASCII values of each character.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "\n", "Example results....");
                    lsStrResult = String.Concat(lsStrResult, "\n", @"                      ConsoleApp1 ASC ThisTestABCDEF");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      84 104 105 115 84 101 115 116 65 66 67 68 69 70");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Above is the result.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Logging Enabled = NULL");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Extended Logging Enabled = 0");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Message = Status is all good.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      ReturnCode = 0");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Runtime = 14.296875");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Version                  = " + lsStrVersionNo);
                    lsStrResult = String.Concat(lsStrResult, "\n", "End of Example results....\n");

                    lsBolValidFunction = true;
                }
                if (lsStrParameter1.ToUpper() == "CONSOLEAPP1" || lsStrParameter1.ToUpper() == "ALL") // Tested
                {
                    // WIP Add more examples such as ConsoleApp1 12.45 2 does not work properly so fix this.
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "CONSOLEAPP1 Function [Parameter1, Parameter2,...", "\n");
                    lsStrResult = String.Concat(lsStrResult, "This calls ConsoleApp1.exe", "\n");

                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function       CONSOLEAPP1   Calls ConsoleApp1", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter1     Function      This is the function that", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter2     CAInstallDir  ConsoleApp1 install directory, defaults to.", "\n");
                    lsStrResult = String.Concat(lsStrResult, @"                             C:\Program Files\TITUS\TITUS Illuminate\CustomFunctions\Content.Extensibility", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                             If the value of  CA InstallDir is S, the the path will default to", "\n");
                    lsStrResult = String.Concat(lsStrResult, @"                             C:\Program Files\TITUS\TITUS Services\EnterpriseClientService\CustomFunctions\Content.Extensibility", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter3     CAWorkingDir  The directory where ConsoleApp1 is going to run.", "\n");

                    lsStrResult = String.Concat(lsStrResult, "Parameter4     Parameter1    Parameter4  on this function provides the value for Parameter1.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter5     Parameter2    Parameter5  on this function provides the value for Parameter2.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter6     Parameter3    Parameter6  on this function provides the value for Parameter3.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter7     Parameter4    Parameter7  on this function provides the value for Parameter4.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter8     Parameter5    Parameter8  on this function provides the value for Parameter5.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter9     Parameter8    Parameter9  on this function provides the value for Parameter6.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter10    Parameter9    Parameter10 on this function provides the value for Parameter7.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter11    Parameter10   Parameter11 on this function provides the value for Parameter8.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter12    Parameter11   Parameter12 on this function provides the value for Parameter9.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter13    Parameter12   Parameter13 on this function provides the value for Parameter10.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter14    Parameter13   Parameter14 on this function provides the value for Parameter11.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter15    Parameter14   Parameter15 on this function provides the value for Parameter12.", "\n");

                    lsBolValidFunction = true;
                }
                if (lsStrParameter1.ToUpper() == "CPCT" || lsStrParameter1.ToUpper() == "ALL") // Tested
                {
                    // WIP Add more examples such as ConsoleApp1 12.45 2 does not work properly so fix this.
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "CPCT text [prec]", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function        CPCT        Multiplies dpct by 100 and appends %.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 1     dpct        decimal number between 0 and 1.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 2     prec        precision or number of numbers to right of decimal, defaults to 0.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "\n", "Example results....");
                    lsStrResult = String.Concat(lsStrResult, "\n", @"                      ConsoleApp1 CPCT .12345 2");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      12.3%");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Above is the result.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Logging Enabled          = NULL");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Extended Logging Enabled = 0");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Message                  = Status is all good.");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      lsStrResult = 12.345");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      ReturnCode               = 0");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Runtime                  = 15.1796875");
                    lsStrResult = String.Concat(lsStrResult, "\n", "                      Version                  = " + lsStrVersionNo);
                    lsStrResult = String.Concat(lsStrResult, "\n", "End of Example results....\n");
                    lsBolValidFunction = true;
                }
                if ((lsStrParameter1.ToUpper() == "DEPLOYMENT" && lsStrParameter2.ToUpper() == "") || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "DEPLOYMENT", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "The following options are available for DEPLOYMENT.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "INTRO                       Describes what Content.Extensibility is.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "SUPPORT                     What is supported and by whom.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "DISTRIBUTION                How to get the the most recent version of the software.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "ADMINCONSOLE                How to deploy for use with the TITUS Administrative console.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "ILLUMINATE                  How to deploy for use with the TITUS Illuminate.", "\n");
                    lsBolValidFunction = true;

                }
                if ((lsStrParameter1.ToUpper() == "DEVELOPMENT") || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "DEVELOPMENT", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Following are bullet points as general guidance for doing development work.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "- When there is an exception, for example attempting to read registry key that does not exists,", "\n");
                    lsStrResult = String.Concat(lsStrResult, "  this should give a return code of other than 0. It should be prefaced the function name used to invoke.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "  For example, RR1 is the return code (lsStrReturnCode)when the registry key is not found.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "- Registry entries in general should be written to", "\n");
                    lsStrResult = String.Concat(lsStrResult, @"  Computer\HKEY_CURRENT_USER\Software\Titus Labs\Custom Conditions\Content.Extensibility", "\n");
                    lsStrResult = String.Concat(lsStrResult, @"  Computer\HKEY_LOCAL_MACHINE\SOFTWARE\TITUS\CustomFunctions\Content.Extensibility", "\n");
                    lsStrResult = String.Concat(lsStrResult, "  These are just suggestions, there may be valid reasons for other locations.", "\n");
                    lsBolValidFunction = true;

                }
                if (lsStrParameter1.ToUpper() == "DIVIDEBYZERO" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "DIVIDEBYZERO", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function        DIVIDEBYZERO  Intentional divide by zero to show logging.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                              No parameters.", "\n");
                    //WIP2  ...business about log output exception, etc.
                    lsBolValidFunction = true;
                }

                if (lsStrParameter1.ToUpper() == "FIRSTLEVEL" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "FIRSTLEVEL", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "FIRSTLEVEL or also first level parameters are optional and specified before other paramaters and only applicable to the command line version.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Their purpose is to easily support the optional parameters which are present in the dynamic property. They dyanmic property has the following properties", "\n");
                    lsStrResult = String.Concat(lsStrResult, "In the Content.Extensibility custom condition, the following parameters are specified:", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter1", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter2", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter3", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter4", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter5", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter6", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter7", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter8", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter9", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter10", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter11", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter12", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter13", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter14", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter15", "\n");
                    lsStrResult = String.Concat(lsStrResult, "EnableLogging", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Configuration", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Rule", "\n");
                    lsStrResult = String.Concat(lsStrResult, "DynamicProperty", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Without the use of first level parameters, the enable logging becomes the 17th parameter. First the", "\n");
                    lsStrResult = String.Concat(lsStrResult, "function name, then 15 parameters, then the switch for logging.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "For example, the syntax below works but provides no means to specify a 17th paramater.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "ConsoleApp1 MID Test 1 2", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "So, the first level paramter LOG is used. For example.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "ConsoleApp1 LOG MID Test 1 2", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "This turns on logging and all the parameters shift so the function MID has a Parameter1 value of Test and so on.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "LOG and NOLOG are the only support first level parameters for the command line version.", "\n");
                    lsBolValidFunction = true;
                }
                if (lsStrParameter1.ToUpper() == "LEN" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "LEN text", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function        LEN         returns the length if text.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 1     text        is the text string you want the length of.", "\n");
                    lsBolValidFunction = true;
                }
                if ((lsStrParameter1.ToUpper() == "LOG" && lsStrParameter2.ToUpper() != "SAMPLE") || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "LOG", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "LOG is a first level parameter.  First level parameters are specified before all other parameters.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "To learn more about first level parameters you can enter HELP FIRSTLEVEL.", "\n");

                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "LOG will turn logging on which is off by defualt.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Content.Extensibility uses Serilog and additional details are available here: ", "\n");
                    lsStrResult = String.Concat(lsStrResult, "The rest of TITUS software uses log4net. The rational to decide which logger was to use was based", "\n");
                    lsStrResult = String.Concat(lsStrResult, "two factors:", "\n");
                    lsStrResult = String.Concat(lsStrResult, "1) There are no standard tools deployed from TITUS using log4net and,", "\n");
                    lsStrResult = String.Concat(lsStrResult, "2) An independent review at: ", "\n");
                    lsStrResult = String.Concat(lsStrResult, "LOG will make a difference in performance. At the time of this writing, the use of LOG", "\n");
                    lsStrResult = String.Concat(lsStrResult, "was found to be a little over five times slower with a runtime of 68.2734375 when LOG is ", "\n");
                    lsStrResult = String.Concat(lsStrResult, "is used versus a runtime of 12.6796875 without log when run without LOG.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Here it is without logging.", "\n");
                    lsStrResult = String.Concat(lsStrResult, @"                        C: \Users\bill.brunt\source\repos\billbrunt\ConsoleApp1\ConsoleApp1\bin\Debug > consoleapp1", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        No function name provided.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        Provide HELP as the first command line parameter", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        or as the Function parameter name for the dynamic", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        property in the TITUS Administration console.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        Above is the result.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        Logging Enabled = NULL", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        Extended Logging Enabled = 0", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        Message = Status is all good.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        ReturnCode = 0", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        Runtime = 12.6796875", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        Version = 2019.03.10.17.26", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Here it is with logging.", "\n");
                    lsStrResult = String.Concat(lsStrResult, @"                        C:\Users\bill.brunt\source\repos\billbrunt\ConsoleApp1\ConsoleApp1\bin\Debug > consoleapp1 LOG", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        No function name provided.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        Provide HELP as the first command line parameter", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        or as the Function parameter name for the dynamic", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        property in the TITUS Administration console.", "\n");

                    lsStrResult = String.Concat(lsStrResult, "                        Above is the result.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        Logging Enabled = TRUE", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        Extended Logging Enabled = 1", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        Message = Status is all good.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        ReturnCode = 0", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        Runtime = 68.2734375", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                        Version = 2019.03.10.17.26", "\n");

                    lsBolValidFunction = true;
                }
                if ((lsStrParameter1.ToUpper() == "LOG" && lsStrParameter2.ToUpper() == "SAMPLE") || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "LOG SAMPLE", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "LOG SAMPLE provides the location of the log, sample output and description.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "The location and name of the log is:", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, @"C:\ProgramData\TITUS>type Content.Extensibility.YYYYMMDD.log", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Where", "\n");
                    lsStrResult = String.Concat(lsStrResult, "YYYY is the year.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "MM is the month.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "DD is the day.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "For example, the following command", "\n");
                    lsStrResult = String.Concat(lsStrResult, @"C:\ProgramData\TITUS>type Content.Extensibility.20190310.log", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "displays the following", "\n");
                    lsStrResult = String.Concat(lsStrResult, @"                        C: \Users\bill.brunt\source\repos\billbrunt\ConsoleApp1\ConsoleApp1\bin\Debug > consoleapp1", "\n");


                    lsBolValidFunction = true;
                }
                if (lsStrParameter1.ToUpper() == "FNDC" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "FNDC text char n", "\n"); // GetNthIndexOfChar(string s, char t, int n)
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function        FNDC        Gets nth index of character in text.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 1     text        text string to search.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 2     char        character to look for within text.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 3     n           occurance of character from begining of text.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "\n");
                    lsStrResult = String.Concat(lsStrResult, "It is suspected, but not tested that FNDC is faster than FIND.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "FNDC may be faster when only looking for a character as", "\n");
                    lsBolValidFunction = true;
                }
                if (lsStrParameter1.ToUpper() == "FIND" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "FIND text char n", "\n"); // GetNthIndexOfChar(string s, char t, int n)
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function        FIND        Gets nth index of txt2 in text.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 1     text        text string to search.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 2     txt2        txt2 to look for within text.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 3     n           occurance of txt2 from begining of text.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "\n");
                    lsStrResult = String.Concat(lsStrResult, "If txt2 is a single character, consider using FNDC as likely quicker (untested)");
                    //lsStrResult = String.Concat(lsStrResult, "NI....................................: NI returns the nth index of txt2 within text.", "\n");
                    // NthIndexOf(this string target, string value, int n)
                    // GetNthIndexOfChar(string s, char t, int n)

                }
                if (lsStrParameter1.ToUpper() == "FWDM" || lsStrParameter1.ToUpper() == "ALL")
                {
                    string lsStrTemp = @"C:\Program Files\TITUS\TITUS Services\EnterpriseClientService\CustomFunctions";

                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "FWDM", "\n");
                    lsStrResult = String.Concat(lsStrResult, "File Write Date Modifed", "\n");
                    //ffff
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter1     filename    This is the full path and file name, like File.Path property in Admin Console for TCD.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter2     dm          This is the value desired to set the data modified to in the format:", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                           'yyyy-MM-dd HH:mm: ssZ' within the single quotes where", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                           the time is UTC as represented by the trailing captial Z.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                           For example '2019-09-29 18:18:21Z' is valid.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                           This format was chosen because it is the same as the TCD property ", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                           'File.ModifiedTimeUtc'", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                           It must match this format to work and no error checking is currently done.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                           [File.ModifiedTimeUtc] can reliably be passed directly in.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter3*    filename    [Optional]  Canary file name for Content.Extensibility.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter4*    dm          [Optional]  Canary's data modifed for Content.Extensibility.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                           If empty and Parameter3 is not, defaults to current date and time.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter5*    filename    [Optional]  Canary for ConsoleApp1.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter6*    dm          [Optional]  Canary's data modifed for ConsoleApp1.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "                           If empty and Parameter5 is not, defaults to current date and time.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter7*    filename    [Optional]  the default is ", lsStrTemp, ".", "\n");
                    lsStrResult = String.Concat(lsStrResult, "* Those with an asterisk are not implemented at this time as parameters.", "\n");
                    lsBolValidFunction = true;
                }
                if (lsStrParameter1.ToUpper() == "LINE" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "LINE text [line_num] [num_lines]", "\n");
                    lsStrResult = String.Concat(lsStrResult, "LINE @file [line_num] [num_lines]", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function        LINE        returns a specific line number.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 1     text        is the text string from which you want to extract the lines.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 1     @file       if Parameter 1 starts with an @ then this will be the full path and filename for text to be read from file.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 2     line_num    if omitted, then a count of all lines is returned.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 3     num_lines   if omitted, defaults to 1, specifies how many lines to return from text.", "\n");
                    lsBolValidFunction = true;
                }
                if (lsStrParameter1.ToUpper() == "MID" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "MID text start_num num_chars", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function        MID         performs as MID in Excel", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 1     text        is the text string from which you want to extract the characters.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 2     start_num   is the position of the first character you want to extract. The first character in Text is 1.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 3     Num_chars   specifies how many characters to return from text.", "\n");
                    lsBolValidFunction = true;
                }
                if (lsStrParameter1.ToUpper() == "NOLOG" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "NOLOG", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "NOLOG is first level parameter.  First level parameters are specified before all other parameters.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "To learn more about first level parameters you can enter HELP FIRSTLEVEL.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter2     matches     dynamnic property result from a content validation profile .Matches ", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "NOLOG means that no logging will take place. This is the default as well even if NOLOG is not specified.", "\n");
                    lsBolValidFunction = true;
                }
                if (lsStrParameter1.ToUpper() == "PRINT" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "PRINT text");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function        PRINT       Returns Parameter unchanged by code.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 1     text        text string to pass in and out of PRINT function.", "\n");
                    lsBolValidFunction = true;
                }
                if (lsStrParameter1.ToUpper() == "RPAD" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "RPAD text, len_text, [pad_str], [str_one]", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function        RPAD        Adds padding characters on the right side of text.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 1     text        is the text string to pad characters on the right.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 2     len_text    is the length the returned text.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 3     pad_str     default is a space, and if specified is the string to pad with.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 4     str_one     true or false, default is false where the string is counted the actual length.", "\n");
                    lsBolValidFunction = true;
                }
                if (lsStrParameter1.ToUpper() == "RTRIM" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "RTRIM text", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function        RTRIM       Removes all spaces on the right side of text.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 1     text        is the text string from which you want spaces on the right removed.", "\n");
                    lsBolValidFunction = true;
                }
                if (lsStrParameter1.ToUpper() == "UPPER" || lsStrParameter1.ToUpper() == "ALL")
                {
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "UPPER text", "\n");
                    lsStrResult = String.Concat(lsStrResult, "", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Function        UPPER       Converts a text string to all uppercase letters.", "\n");
                    lsStrResult = String.Concat(lsStrResult, "Parameter 1     text        is the text string to convert to upper case.", "\n");
                    lsBolValidFunction = true;
                }


                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "KV")
            {
                // C:\ProgramData\Titus\CustomResources\Content.Extensibility\kv\_nti40\bin>filter c:\temp5\Aerial_Requirements.doc c:\temp5\Aerial_Requirements.doc.txt
                try
                {
                    var newFile = new FileInfo(lsStrParameter1);
                    string newFileName = String.Concat(Environment.GetEnvironmentVariable("temp"), @"\", DateTime.Now.Ticks.ToString(), ".txt");
                    string lsStrArguments = String.Concat(@"""", lsStrParameter1, @""" """, newFileName, @"""");
                    if (File.Exists(lsStrParameter1))
                    {
                        if (lsStrParameter2 == "")
                        {
                            lsStrParameter2 = @"c:\Program Files\Titus\TITUS Illuminate\CustomFunctions\kv\_nti40\bin";
                        }
                        string lsStrProcessToRun = String.Concat(lsStrParameter2, @"\", "filter.exe");
                        //System.IO.File.WriteAllText(@"c:\temp5\KV01.txt", String.Concat("lsStrParameter1 = ", lsStrParameter1));
                        //System.IO.File.WriteAllText(@"c:\temp5\KV02.txt", String.Concat("lsStrParameter2 = ", lsStrParameter2));
                        //System.IO.File.WriteAllText(@"c:\temp5\KV03.txt", String.Concat("lsStrArguments = ", lsStrArguments));
                        //System.IO.File.WriteAllText(@"c:\temp5\KV04.txt", String.Concat("newFileName = ", newFileName));
                        //System.IO.File.WriteAllText(@"c:\temp5\KV05.txt", String.Concat("lsStrProcessToRun = ", lsStrProcessToRun));
                        // Console.WriteLine(String.Concat("lsStrProcessToRun = ", lsStrProcessToRun, "\n", "lsStrParameter2 = ", lsStrParameter2));
                        if (File.Exists(lsStrProcessToRun))
                        {
                            ProcessStartInfo cmdsi = new ProcessStartInfo(lsStrProcessToRun);
                            cmdsi.Arguments = lsStrArguments;
                            cmdsi.RedirectStandardOutput = true;
                            cmdsi.UseShellExecute = false;
                            cmdsi.WorkingDirectory = lsStrParameter2;

                            Process cmd1 = Process.Start(cmdsi);
                            cmd1.WaitForExit();
                            // Console.WriteLine("newFileName = {0}", newFileName);
                            var varFileInfo = new FileInfo(newFileName);
                            if (varFileInfo.Length != 0)  //ttttttt
                            {
                                lsStrResult = File.ReadAllText(newFileName);
                                File.Delete(newFileName);
                            }
                            else
                            {
                                lsStrReturnCode = "-1";
                                lsStrMessage = "Key View filter.exe returned no text. Likely image. Classify manually.";
                            }
                        }
                        else
                        {
                            lsStrReturnCode = "-2";
                            lsStrMessage = String.Concat("filter.exe not found at: ", lsStrProcessToRun);
                        }
                    }
                    else
                    {
                        lsStrMessage = String.Concat("No input file found at: ", lsStrParameter1);
                    }
                }
                catch (Exception ex)
                {
                    //System.IO.File.WriteAllText(@"c:\temp5\KVError01.txt", String.Concat(ex.ToString()));
                    lsStrMessage = String.Concat("Catch (Exception ex) occurred with Function:", lsStrFunction.ToUpper());
                    lsStrMessage = String.Concat(lsStrMessage, "\n", ex.ToString());
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "LEN")
            {
                String lsStrTextToProcess = lsStrParameter1;
                //resultContainer["DoesTheFileExist"] = fileExists ? "True" : "False";
                lsBolExceptionTrapped = fncBolGetContents(ref lsStrReturnCode, ref lsStrTextToProcess, lsStrSoftwareRunning, lsStrLoggingEnabled, lsStrExtendedLoggingEnabled) ? true : false;
                lsStrResult = lsBolExceptionTrapped ? lsStrTextToProcess.Length.ToString() : lsStrTextToProcess;
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "LINE")
            {

                string lsStrTextToProcess = lsStrParameter1;
                lsBolExceptionTrapped = fncBolGetContents(ref lsStrReturnCode, ref lsStrTextToProcess, lsStrSoftwareRunning, lsStrLoggingEnabled, lsStrExtendedLoggingEnabled) ? false : true;
                if (lsBolExceptionTrapped == true)
                {
                    lsStrResult = lsStrTextToProcess;
                }
                else
                {
                    int lsIntUnicodeLF = 10;
                    char characterLF = (char)lsIntUnicodeLF;
                    string lsStrTextLF = characterLF.ToString();

                    int unicodeCR = 13;
                    char characterCR = (char)unicodeCR;
                    string lsStrTextCR = characterCR.ToString();

                    String lsStrEOLDelimiter = String.Concat(lsStrTextCR, lsStrTextLF);
                    String lsStrEasierToParse = String.Concat(lsStrEOLDelimiter, lsStrTextToProcess, lsStrEOLDelimiter);
                    int lsIntLenEOLDelimiter = lsStrEOLDelimiter.Length;


                    if (lsStrParameter2 == "")
                    {
                        if (lsStrLoggingEnabled.ToUpper() == "TRUE")
                        {
                            //Log.Debug($"{lsStrConfigObject} Parameter 2 is NULL so counting end of lines.");

                        }
                        lsStrResult = (TextTool.CountStringOccurrences(lsStrTextToProcess, lsStrEOLDelimiter) + 1).ToString();
                    }
                    else
                    {
                        int lsIntStartOfLines = TextTool.NthIndexOf(lsStrEasierToParse, lsStrEOLDelimiter, Int32.Parse(lsStrParameter2));
                        int lsIntNumberOfLines = 0;
                        if (lsStrParameter3 == "")
                        {
                            lsIntNumberOfLines = 1;
                        }
                        else
                        {
                            lsIntNumberOfLines = Int32.Parse(lsStrParameter3);
                        }
                        int lsIntEndOfLines = TextTool.NthIndexOf(lsStrEasierToParse, lsStrEOLDelimiter, Int32.Parse(lsStrParameter2) + lsIntNumberOfLines);
                        int lsIntCharactersToReturn = lsIntEndOfLines - lsIntStartOfLines;
                        try
                        {
                            lsStrResult = lsStrEasierToParse.Substring(lsIntStartOfLines + lsStrEOLDelimiter.Length, lsIntCharactersToReturn - lsStrEOLDelimiter.Length);
                        }
                        catch (Exception ex)
                        {
                            //Log.Error("lsStrEasierToParse.Substring(lsIntStartOfLines + lsStrEOLDelimiter.Length, lsIntCharactersToReturn - lsStrEOLDelimiter.Length) failed with exception:");
                            //Log.Error("{0}", ex);
                            //Log.Error("lsIntStartOfLines = {0}", lsIntStartOfLines);
                            //Log.Error("lsStrEOLDelimiter.Length = {0}", lsStrEOLDelimiter.Length);
                            //Log.Error("lsIntCharactersToReturn = {0}", lsIntCharactersToReturn);
                            //Log.Error("lsIntStartOfLines + lsStrEOLDelimiter.Length = {0}", lsIntStartOfLines + lsStrEOLDelimiter.Length);
                            //Log.Error("lsIntCharactersToReturn - lsStrEOLDelimiter.Length = {0}", lsIntCharactersToReturn - lsStrEOLDelimiter.Length);
                            lsStrMessage = String.Concat(lsStrMessage, "\n", "LINE didn't work. Status no longer all good.");
                            lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrEasierToParse.Substring(lsIntStartOfLines + lsStrEOLDelimiter.Length, lsIntCharactersToReturn - lsStrEOLDelimiter.Length) failed with exception:");
                            lsStrMessage = String.Concat(lsStrMessage, "\n", ex.ToString());
                            lsStrMessage = String.Concat(lsStrMessage, "\n", "lsIntStartOfLines                                  = ", lsIntStartOfLines);
                            lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrEOLDelimiter.Length                           = ", lsStrEOLDelimiter.Length);
                            lsStrMessage = String.Concat(lsStrMessage, "\n", "lsIntCharactersToReturn                            = ", lsIntCharactersToReturn);
                            lsStrMessage = String.Concat(lsStrMessage, "\n", "lsIntStartOfLines + lsStrEOLDelimiter.Length       = ", lsIntStartOfLines + lsStrEOLDelimiter.Length);
                            lsStrMessage = String.Concat(lsStrMessage, "\n", "lsIntCharactersToReturn - lsStrEOLDelimiter.Length = ", lsIntCharactersToReturn - lsStrEOLDelimiter.Length);

                        }
                    }
                    //String lsStrASC = "";
                    //foreach (byte b in System.Text.Encoding.UTF8.GetBytes(lsStrResult.ToCharArray()))
                    //    lsStrASC = String.Concat(lsStrASC, b.ToString(), " ");
                    //System.Console.WriteLine("lsStrASC = {0}", lsStrASC);
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "MD5")
            {
                //string lsStrfilename = @"C:\Users\Public\Downloads\testfile.txt";
                if (lsStrParameter2.ToUpper() == "FILE" || lsStrParameter2.ToUpper() == "")
                {
                    using (var md5 = MD5.Create())
                    {
                        using (var stream = File.OpenRead(lsStrParameter1))
                        {
                            var hash = md5.ComputeHash(stream);
                            lsStrResult = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                        }
                    }
                    lsBolValidFunction = true;
                }
                if (lsStrParameter2.ToUpper() == "CONTENT")
                {
                    using (var md5 = MD5.Create())
                    {
                        byte[] byteArray = System.Text.Encoding.ASCII.GetBytes(lsStrParameter1);
                        using (var stream = new MemoryStream(byteArray))
                        {
                            var hash = md5.ComputeHash(stream);
                            lsStrResult = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                        }
                    }
                    lsBolValidFunction = true;
                }
            }
            if (lsStrFunction.ToUpper() == "MID")
            {
                if (lsStrExtendedLoggingEnabled == "1")
                {
                    //Log.Debug(lsStrConfigObject, " ", "lsStrFunction = {0}", lsStrFunction);
                    //Log.Debug(lsStrConfigObject, " ", "lsStrParameter1 = {0}", lsStrParameter1);
                    //Log.Debug(lsStrConfigObject, " ", "lsStrParameter2 = {0}", lsStrParameter2);
                    //Log.Debug(lsStrConfigObject, " ", "lsStrParameter3 = {0}", lsStrParameter3);
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Extended logging enabled.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrFunction = ", lsStrFunction);
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrParameter1 = ", lsStrParameter1);
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrParameter2 = ", lsStrParameter2);
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrParameter3 = ", lsStrParameter3);
                }
                try
                {
                    lsStrResult = lsStrParameter1.Substring(Int32.Parse(lsStrParameter2) - 1, Int32.Parse(lsStrParameter3));
                }
                catch (Exception ex)
                {
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Looks like the MID function had an exception.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", ex);
                    //Log.Error(ex, "Exception is {0}");
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "PRINT")
            {
                // Function        PRINT       Returns Parameter unchanged by code.
                // Parameter 1     text        text string to pass in and out of PRINT function.
                lsStrResult = lsStrParameter1;
                lsStrResult = string.Concat(lsStrResult, lsStrParameter2 == "" ? "" : string.Concat("\n", lsStrParameter2));
                lsStrResult = string.Concat(lsStrResult, lsStrParameter3 == "" ? "" : string.Concat("\n", lsStrParameter3));
                lsStrResult = string.Concat(lsStrResult, lsStrParameter4 == "" ? "" : string.Concat("\n", lsStrParameter4));
                lsStrResult = string.Concat(lsStrResult, lsStrParameter5 == "" ? "" : string.Concat("\n", lsStrParameter5));
                lsStrResult = string.Concat(lsStrResult, lsStrParameter6 == "" ? "" : string.Concat("\n", lsStrParameter6));
                lsStrResult = string.Concat(lsStrResult, lsStrParameter7 == "" ? "" : string.Concat("\n", lsStrParameter7));
                lsStrResult = string.Concat(lsStrResult, lsStrParameter8 == "" ? "" : string.Concat("\n", lsStrParameter8));
                lsStrResult = string.Concat(lsStrResult, lsStrParameter9 == "" ? "" : string.Concat("\n", lsStrParameter9));
                lsStrResult = string.Concat(lsStrResult, lsStrParameter10 == "" ? "" : string.Concat("\n", lsStrParameter10));
                lsStrResult = string.Concat(lsStrResult, lsStrParameter11 == "" ? "" : string.Concat("\n", lsStrParameter11));
                lsStrResult = string.Concat(lsStrResult, lsStrParameter12 == "" ? "" : string.Concat("\n", lsStrParameter12));
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "RAND")
            {
                if (lsStrExtendedLoggingEnabled == "1")
                {
                    //Log.Debug(lsStrConfigObject, " ", "lsStrFunction = {0}", lsStrFunction);
                    //Log.Debug(lsStrConfigObject, " ", "lsStrParameter1 = {0}", lsStrParameter1);
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Extended logging enabled.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrFunction = ", lsStrFunction);
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "lsStrParameter1 = ", lsStrParameter1);
                }
                try
                {
                    var rand = new Random();
                    lsStrResult = rand.Next(2147483647).ToString().PadLeft(11, '0') + rand.Next(2147483647).ToString().PadLeft(11, '0') + rand.Next(2147483647).ToString().PadLeft(11, '0');
                }
                catch (Exception ex)
                {
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Looks like the ", lsStrFunction.ToUpper(), " function had an exception.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", ex);
                    //Log.Error(ex, "Exception is {0}");
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "RNLOOKUP")
            {
                // ConsoleApp1 RNLOOKUP 0.23 NONE,0,0,LOW,0,0.25,MEDIUM,0.26,0.5,HIGH,0.51,0.75,CRIITCAL,0.76,1
                // LOW
                // Above is the result.
                //
                // ConsoleApp1 RNLOOKUP 0.63 "Public,0,0,General Business,0,0.25,Confidential,0.26,0.5,Internal,0.51,0.75,Restricted,0.76,1"
                // Internal
                // Above is the result.
                //

                string[] words = lsStrParameter2.Split(',');
                try
                {
                    int lsIntLookupEntries = words.GetLength(0) - 1;
                    for (int i = 0; i <= lsIntLookupEntries; i = i + 3)
                    {
                        if (
                            (float.Parse(lsStrParameter1) >= float.Parse(words[i + 1]) && float.Parse(lsStrParameter1) < float.Parse(words[i + 2]) && i + 2 != lsIntLookupEntries) ||
                            (float.Parse(lsStrParameter1) >= float.Parse(words[i + 1]) && float.Parse(lsStrParameter1) <= float.Parse(words[i + 2]) && i + 2 == lsIntLookupEntries)
                            )
                        {
                            lsStrResult = words[i];
                        }
                    }
                }
                catch (Exception ex)
                {
                    if (lsStrLoggingEnabled.ToUpper() == "TRUE")
                    {
                        //Log.Error($"{lsStrConfigObject} Error with +. More details available from extended logging.");
                        if (lsStrExtendedLoggingEnabled == "1")
                        {
                            //Log.Error(String.Concat(lsStrConfigObject, " ", ex.ToString()));
                        }
                    }
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Oops. It was caught inside + with:", lsStrFunction, "\n");
                    lsStrMessage = String.Concat(lsStrMessage, ex.ToString());
                    lsBolExceptionTrapped = true;
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "RPAD")
            {
                // Function        RPAD        Adds padding characters on the right side of text
                // Parameter 1     text        is the text string to pad characters on the right.
                // Parameter 2     len_text    is the length of the returned text.
                // Parameter 3     pad_str     default is a space, and if specified is the string to pad with.
                // Parameter 4     str_one     true or false, default is false where the string is counted the actual length.
                if (lsStrParameter3.Length == 1)
                {
                    char[] lsChrParameter3 = lsStrParameter3.ToCharArray();
                    lsStrResult = lsStrParameter1.PadRight(Int32.Parse(lsStrParameter2), lsChrParameter3[0]);
                }
                else
                {
                    lsStrResult = lsStrParameter1;
                    int lsIntRemainingCharacters = Int32.Parse(lsStrParameter2) - lsStrParameter1.Length;
                    for (int i = 0; i < lsIntRemainingCharacters; i++)
                    {
                        //System.Console.Write("i = {0} ",i);
                        lsStrResult = String.Concat(lsStrResult, lsStrParameter3);
                    }
                    if (lsStrParameter4 == "false" || lsStrParameter4 == "")
                    {
                        lsStrResult = lsStrResult.Substring(0, Int32.Parse(lsStrParameter2));
                    }
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "RF")
            {
                lsStrResult = File.ReadAllText(lsStrParameter1);
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "RR")
            {
                string lsStrDefaultApplyMarkingsRegKey = lsStrSoftwareRunning == "ConsoleApp1.exe" ? @"SOFTWARE\WOW6432Node\TITUS\CustomFunctions\Content.Extensibility" : @"SOFTWARE\TITUS\CustomFunctions\Content.Extensibility";
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(lsStrDefaultApplyMarkingsRegKey))
                {
                    //key.SetValue("DefaultApplyMarkings","red");
                    Object k = key.GetValue("DefaultApplyMarkings");
                    lsStrResult = k.ToString();
                }
                #region old stuff
                //string registryValue = string.Empty;
                //RegistryKey localKey = null;
                //if (Environment.Is64BitOperatingSystem)
                //{
                //    localKey = RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.CurrentUser, RegistryView.Registry64);
                //}
                //else
                //{
                //    localKey = RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.CurrentUser, RegistryView.Registry32);
                //}

                //try
                //{
                //    Console.WriteLine(lsStrParameter1);
                //    Console.WriteLine(lsStrParameter2);
                //    // SOFTWARE\Titus Labs\Custom Conditions2\Content.Extensibility
                //    // @"SOFTWARE\\Policies\\TITUS\\ServiceLocation"
                //    //lsStrParameter1 = @"SOFTWARE\\Policies\\TITUS";
                //    //lsStrParameter2 = "Sample";
                //    localKey = localKey.OpenSubKey(lsStrParameter1);
                //    lsStrResult = localKey.GetValue(lsStrParameter2).ToString();
                //}
                //catch (NullReferenceException ex)
                //{
                //    Console.WriteLine(ex.ToString().Substring(0, 84));
                //    if (ex.ToString().Substring(0, 84) == "System.NullReferenceException: Object reference not set to an instance of an object.")
                //    {
                //        // String.Concat($"{lsStrConfigObject}", @" (key != null) evaluates to ", $"True")
                //        lsStrReturnCode = "RR1";
                //        lsStrResult = String.Concat("There appears to be no registry entry for: ", $"{lsStrParameter1}", @"\", $"{lsStrParameter2}");
                //    }
                //    else
                //    {
                //        lsStrMessage = String.Concat(lsStrMessage, "\n", "Looks like the RR function had an exception.");
                //        lsStrMessage = String.Concat(lsStrMessage, "\n", ex);
                //        Log.Error(ex, "Exception is {0}");
                //    }
                //}
                #endregion
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "RTRIM")
            {

                String lsStrTrimChars = lsStrParameter2.Substring(0, 1);

                int lsIntUnicodeSpace = 32;
                char characterSpace = (char)lsIntUnicodeSpace;
                string lsStrTextSpace = characterSpace.ToString();

                char[] lsChrTrimChars = lsStrParameter2.ToCharArray();
                if (lsStrParameter2.Substring(0, 1) == "")
                {
                    lsChrTrimChars[0] = ' ';
                }
                lsStrResult = lsStrTrimChars = lsStrParameter2.TrimEnd(lsChrTrimChars[0]);
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "SDE") // Select Dialog Extension
            {

                try
                {
                    //  lsStrParameter1     unique file name, i.e. GUID for this rule to save and retrieve results from 
                    //  lsStrParameter2     temp directory where file is written and read from 
                    #region Check for filename being passed in.
                    //
                    // Check for filename being passed in.
                    //
                    string lsStrFileName ="";
                    string lsStrtemppath = @"C:\temp\";
                    string lsStrSDEDebug = "Start\n";
                    if (lsStrParameter1 == "")
                    {
                        lsStrReturnCode = "-2";
                        lsStrMessage = String.Concat("Parameter1 is blank and is a required field. Any unqiue GUID will do which can be valid filename.","\n");
                    }
                    else
                    {
                        lsStrFileName = String.Concat(lsStrParameter1,".SDE.txt");
                    }
                    #endregion
                    #region (NOT COMPLETE) Check for name being passed in is valid to use as file name
                    //
                    // Check for name being passed in is valid to use as file name
                    //
                    //---------------------------------------------------------------------------------
                    // Not complete lsStrReturnCode = "-4";
                    //---------------------------------------------------------------------------------
                    #endregion
                    #region Check for path being passed in to write/read results is passed and if not, keep default of c:\temp set in beginning
                    //
                    // Check for path being passed in to write/read results is passed and if not, keep default of c:\temp set in beginning
                    //
                    string lsStrPathComingFrom = @"lsStrtemppath hard coded as 'c:\temp' since Parameter1 was blank when called";
                    if (lsStrParameter2 != "" && lsStrReturnCode=="0")
                    {
                        lsStrtemppath = lsStrParameter2;
                        lsStrPathComingFrom = "Parameter2";
                    }
                    #endregion
                    #region Check to make sure temp directory for writing and reading results from is valid
                    //
                    // Check to make sure temp directory for writing and reading results from is valid
                    //
                    lsStrSDEDebug = String.Concat(lsStrSDEDebug, "lsStrtemppath = ", lsStrtemppath, "\n"); ;
                    System.IO.File.WriteAllText(@"c:\temp\SDEDebug01.txt", lsStrSDEDebug);
                    if (!Directory.Exists(lsStrtemppath) && lsStrReturnCode == "0")
                    {
                        lsStrReturnCode = "-3";
                        lsStrMessage = String.Concat("Temp directory to write SDE result: ", lsStrtemppath, " does not exist and it came from: ", "\n");
                        lsStrMessage = String.Concat(lsStrMessage, lsStrPathComingFrom, "\n", "and lsStrtemppath was ", lsStrtemppath, "\n");
                        lsStrMessage = String.Concat(lsStrMessage, "Please create this directory or specificy one that does in the config.\n");
                    }
                    #endregion
                    #region
                    //
                    // Since policy runs again when after a SET CLASSIFICATION action, then
                    // the first time it is called, pop up the form, the form write out the results, read then and then exit
                    // the next time it comes in, just read the results and pass back without popping up the form.
                    // 
                    if (lsStrReturnCode == "0") {
                        string lsStrfilepath = lsStrtemppath + @"\" + lsStrFileName;
                        lsStrSDEDebug = String.Concat(lsStrSDEDebug, "lsStrfilepath = ", lsStrfilepath, "\n"); ;
                        System.IO.File.WriteAllText(@"c:\temp\SDEDebug02.txt", lsStrSDEDebug);

                        if (!File.Exists(lsStrfilepath))
                        {
                            bool lsbolProcessRunning = ProcessAsUser.Launch(@"C:\Program Files\Titus\Titus Services\EnterpriseClientService\CustomFunctions\SelectDialogExtension\SelectDialogExtension.exe " + lsStrParameter1);
                            Process[] ps = Process.GetProcessesByName("SelectDialogExtension");
                            Process ProcessID = ps[0];
                            QueryFile.BringProcessToFront(ProcessID);
                            ActivateWindow(ProcessID.MainWindowHandle);
                            ProcessID.WaitForExit();
                            lsStrResult = File.ReadAllText(lsStrfilepath);
                            lsStrMessage = "Results read from: " + lsStrfilepath;
                            lsStrReturnCode = "0";
                        }
                        else
                        {
                            lsStrResult = File.ReadAllText(lsStrfilepath);
                            lsStrMessage = "Results read from: " + lsStrfilepath;
                            lsStrReturnCode = "0";
                            File.Delete(lsStrfilepath);
                        }
                    }
                    #endregion
                    // Note: we had to add Local Service using this.. https://support.faxmaker.gfi.com/hc/en-us/articles/360015152239-How-do-I-configure-a-user-account-to-have-logon-as-a-service-permissions-
                    #region old stuff
                    //Thread.Sleep(1000);
                    // https://www.codeproject.com/Articles/7305/Keyboard-Events-Simulation-using-keybd-event-funct
                    //keybd_event(0x12, 0xB8, 0, 0); //Alt Press
                    //keybd_event(0x10, 0xAA, 0, 0); //Shift Press
                    //keybd_event(0x09, 0x8F, 0, 0); // Tab Press
                    //keybd_event(0x12, 0xB8, 0x0002, 0); // Alt Release
                    //keybd_event(0x10, 0xAA, 0x0002, 0); // Shift Release
                    //keybd_event(0x09, 0x8F, 0x0002, 0); // Tab Release

                    //SendKeys.Send("%+{TAB}");

                    //System.Diagnostics.Process proc = new System.Diagnostics.Process();
                    // System.Security.SecureString ssPwd = new System.Security.SecureString();

                    //proc.StartInfo.UseShellExecute = false;
                    // C:\Program Files\Titus\Titus Services\EnterpriseClientService\CustomFunctions\SelectDialogExtension\SelectDialogExtension.exe
                    // proc.StartInfo.FileName = @"C:\Users\bob\OneDrive - TITUS SE 1\source\repos\SelectDialogExtension\SelectDialogExtension\bin\Debug\SelectDialogExtension.exe";
                    //proc.StartInfo.FileName = @"C:\Program Files\Titus\Titus Services\EnterpriseClientService\CustomFunctions\SelectDialogExtension\SelectDialogExtension.exe";
                    //proc.StartInfo.FileName = @"cmd.exe";
                    //ProcessStartInfo cmdsi = new ProcessStartInfo(@"C:\Program Files\Titus\Titus Services\EnterpriseClientService\CustomFunctions\SelectDialogExtension\SelectDialogExtension.exe");
                    //ProcessStartInfo cmdsi = new ProcessStartInfo(@"C:\Users\bob\OneDrive - TITUS SE 1\source\repos\ConsoleApp1\ConsoleApp1\bin\Debug\consoleapp1.exe");

                    //cmdsi.Arguments = lsStrclockTicks;
                    //cmdsi.RedirectStandardOutput = false;
                    //cmdsi.UseShellExecute = false;

                    //------------------------------------------------
                    //cmdsi.Domain = "tituscloud";
                    //cmdsi.UserName = "bob";
                    //string password = "Titus1.";
                    //for (int x = 0; x < password.Length; x++)
                    //{
                    //    ssPwd.AppendChar(password[x]);
                    //}
                    //password = "";
                    //cmdsi.Password = ssPwd;
                    ////------------------------------------------------
                    //Process cmd1 = Process.Start(cmdsi);
                    //cmd1.WaitForExit();
                    //// proc.ExitCode
                    //string lsStrtemppath = System.IO.Path.GetlsStrtemppath();
                    //lsStrMessage = lsStrtemppath + lsStrFileName;
                    //string filepath = lsStrtemppath + lsStrFileName;
                    //if (File.Exists(filepath))
                    //{
                    //    lsStrResult = File.ReadAllText(filepath);
                    //    lsStrResult = "Hello World 1";
                    //    lsStrMessage = lsStrResult;
                    //    lsStrReturnCode = "0";
                    //}
                    //else
                    //{
                    //    lsStrMessage = "File does not exist, did the user cancel?\n";
                    //    lsStrReturnCode = "-1";
                    //}
                    //------------------------------------------------------------------------------------------------------------------------------------------
                    // search for "View more detail from my previous answer I have created an nuget package Nuget"
                    // on the page https://stackoverflow.com/questions/125341/how-do-you-do-impersonation-in-net/7250145#7250145
                    //string login = "bob";
                    //string domain = "tituscloud";  // or could be tituscloud.local
                    //string password = "Titus1.";

                    //using (UserImpersonation user = new UserImpersonation(login, domain, password))
                    //{
                    //    if (user.ImpersonateValidUser())
                    //    {
                    //        // File.WriteAllText("test.txt", "your text");
                    //        // Console.WriteLine("File writed");
                    //        // lsStrParameter1 = Directory where SelectDialogExtension.exe is installed
                    //        // lsStrParameter2 = Working directory where execution will run
                    //        // lsStrParameter3 = Directory file will be written by SelectDialogExtension, read by this function and then deletedd
                    //        if (lsStrParameter1 == "") lsStrParameter1 = @"C:\";
                    //        if (lsStrParameter2 == "") lsStrParameter2 = @"C:\";
                    //        if (lsStrParameter1 == "") lsStrParameter1 = @"C:\";
                    //        //string lsStrWorkingDirectory = "C:\\Users\\bob\\source\\repos\\SelectDialogExtension\\SelectDialogExtension\\bin\\Debug\\";
                    //        string lsStrclockTicks = DateTime.Now.Ticks.ToString();
                    //        string lsStrFileName = String.Concat(lsStrclockTicks, ".SDE.txt");
                    //        String command = lsStrclockTicks;
                    //        // C:\Users\bob\OneDrive - TITUS SE 1\source\repos\SelectDialogExtension\SelectDialogExtension\bin\Debug
                    //        // ProcessStartInfo cmdsi = new ProcessStartInfo("C:\\Users\\bob\\source\\repos\\SelectDialogExtension\\SelectDialogExtension\\bin\\Debug\\SelectDialogExtension.exe");
                    //        ProcessStartInfo cmdsi = new ProcessStartInfo("C:\\Users\\bob\\OneDrive - TITUS SE 1\\source\\repos\\SelectDialogExtension\\SelectDialogExtension\\bin\\Debug\\SelectDialogExtension.exe");
                    //        cmdsi.Arguments = command;
                    //        cmdsi.RedirectStandardOutput = true; // added xx
                    //        cmdsi.UseShellExecute = false; // added xx
                    //                                       //cmdsi.WorkingDirectory = lsStrWorkingDirectory;
                    //        Process cmd1 = Process.Start(cmdsi);
                    //        cmd1.WaitForExit();
                    //        string lsStrtemppath = System.IO.Path.GetlsStrtemppath();
                    //        lsStrMessage = lsStrtemppath + lsStrFileName;
                    //        string filepath = lsStrtemppath + lsStrFileName;
                    //        if (File.Exists(filepath))
                    //        {
                    //            lsStrResult = File.ReadAllText(filepath);
                    //            lsStrMessage = lsStrResult;
                    //            lsStrReturnCode = "0";
                    //        }
                    //        else
                    //        {
                    //            lsStrMessage = "File does not exist, did the user cancel?\n";
                    //            lsStrReturnCode = "-1";
                    //        }
                    //    }
                    //    else
                    //    {
                    //        Console.WriteLine("User not connected");
                    //    }
                    //}
                    //------------------------------------------------------------------------------------------------------------------------------------------
                    // https://stackoverflow.com/questions/125341/how-do-you-do-impersonation-in-net/7250145#7250145
                    // Search for "Philip Allan-Harding"
                    //
                    //            private const string LOGIN = "mamy";
                    //private const string DOMAIN = "mongo";
                    //private const string PASSWORD = "HelloMongo2017";
                    //using (Impersonator user = new Impersonator(LOGIN, DOMAIN, PASSWORD, LogonType.LOGON32_LOGON_NEW_CREDENTIALS, LogonProvider.LOGON32_PROVIDER_WINNT50))
                    //{
                    //}
                    #endregion
                }
                catch (Exception ex)
                {
                    //Log.Error(ex, "GNIC didn't work.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "SDE didn't work.");
                    lsStrMessage = String.Concat(lsStrMessage, "\n", ex.ToString());
                    if (lsStrReturnCode == "0")
                    {
                        lsStrReturnCode = "-1";
                        lsStrMessage = String.Concat("Unknown Error in ", lsStrSoftwareRunning, " in function: ", lsStrFunction, "\n", lsStrMessage, "\n", ex.ToString());
                    }
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "SHA256")
            {
                //string lsStrfilename = @"C:\Users\Public\Downloads\testfile.txt";
                using (var sha256 = SHA256.Create())
                {
                    using (var stream = File.OpenRead(lsStrParameter1))
                    {
                        var hash = sha256.ComputeHash(stream);
                        lsStrResult = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                    }
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "SQL")
            {
                try
                {
                    SqlConnection conn = new SqlConnection("Data Source=DC1\\SQL_Titus;Initial Catalog=TITUS_Illuminate;Integrated Security=SSPI");
                    SqlDataReader SQLresults;
                    conn.Open();
                    SqlCommand cmd = new SqlCommand(lsStrParameter1, conn);  // ("select * from TI.InventoryBox"
                    SQLresults = cmd.ExecuteReader();


                    while (SQLresults.Read())
                    {
                        lsStrResult = String.Concat(lsStrResult, ",", Convert.ToString(SQLresults[0]));
                    }
                    if (SQLresults != null)
                    {
                        SQLresults.Close();
                    }
                    if (conn != null)
                    {
                        conn.Close();
                    }
                    if (lsStrResult.Length > 2)
                    {
                        lsStrResult = lsStrResult.Substring(1, lsStrResult.Length - 1);
                    }
                }
                catch (Exception ex)
                {
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Exception in function SQL: {0}", ex);
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "TAPPREP")
            {
                try
                {
                    string lsStrTextToProcess = lsStrParameter1;
                    lsBolExceptionTrapped = fncBolGetContents(ref lsStrReturnCode, ref lsStrTextToProcess, lsStrSoftwareRunning, lsStrLoggingEnabled, lsStrExtendedLoggingEnabled) ? false : true;
                    if (lsBolExceptionTrapped == true)
                    {
                        lsStrMessage = lsStrTextToProcess;
                    }
                    else
                    {
                        lsStrResult = lsStrTextToProcess.Replace(System.Environment.NewLine, String.Concat(",", System.Environment.NewLine));
                        lsStrResult = String.Concat("The fact that ", lsStrResult, ",");
                    }
                }
                catch (Exception ex)
                {
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Message in TAPPREP error: {0}", ex);
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "UPPER")
            {
                lsStrResult = lsStrParameter1.ToUpper();
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "VERSION")
            {

                try
                {
                    lsStrResult = lsStrVersionNo;
                }
                catch (Exception ex)
                {
                    if (lsStrLoggingEnabled.ToUpper() == "TRUE")
                    {
                        //Log.Error($"{lsStrConfigObject} Error with +. More details available from extended logging.");
                        if (lsStrExtendedLoggingEnabled == "1")
                        {
                            //Log.Error(String.Concat(lsStrConfigObject, " ", ex.ToString()));
                        }
                    }
                    lsStrMessage = String.Concat(lsStrMessage, "\n", "Oops. It was caught inside + with:", lsStrFunction, "\n");
                    lsStrMessage = String.Concat(lsStrMessage, ex.ToString());
                    lsBolExceptionTrapped = true;
                }
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "WSER")
            //All the following code that is commented until it is not is from Eugene Low
            {
                //    //                        psStrContents = File.ReadAllText(psStrContents);
                //    string html = string.Empty;
                //    string url = parameters[0];
                //    HttpWebResponse response = null;

                //    try
                //    {
                //        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                //        request.AutomaticDecompression = DecompressionMethods.GZip;
                //        var postData = parameters[1];
                //        var data = Encoding.ASCII.GetBytes(postData);

                //        if (string.Equals(parameters[0], "true", StringComparison.CurrentCultureIgnoreCase))
                //        {
                //            request.Method = "POST";
                //            //request.ContentType = "application/x-www-form-urlencoded";
                //            request.ContentLength = data.Length;

                //            // Set the ContentType property of the WebRequest.  
                //            request.ContentType = "application/x-www-form-urlencoded";

                //            // Get the request stream.  
                //            Stream dataStream = request.GetRequestStream();
                //            // Write the data to the request stream.  
                //            dataStream.Write(data, 0, data.Length);
                //            // Close the Stream object.  
                //            dataStream.Close();
                //            // Get the response.  
                //        }


                //        using (response = (HttpWebResponse)request.GetResponse())
                //        using (Stream stream = response.GetResponseStream())
                //        using (StreamReader reader = new StreamReader(stream))
                //        {
                //            html = reader.ReadToEnd();
                //        }
                //    }
                //    catch (WebException e)
                //    {
                //        if (e.Status == WebExceptionStatus.ProtocolError)
                //        {
                //            response = (HttpWebResponse)e.Response;
                //            html = "Errorcode: " + (int)response.StatusCode;
                //        }
                //        else
                //        {
                //            html = "Error: " + e.Status;
                //        }
                //    }
                //    finally
                //    {
                //        if (response != null)
                //        {
                //            response.Close();
                //        }
                //    }

                //    Console.WriteLine(html);
                //    resultMessage = html;
                //    resultContainer["WSOutput"] = html;
                //    //resultContainer["Para2"] = "0";
                //    lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "WF")
            {
                //                        psStrContents = File.ReadAllText(psStrContents);
                System.IO.File.WriteAllText(lsStrParameter1, lsStrParameter2);
                lsBolValidFunction = true;
            }
            if (lsStrFunction.ToUpper() == "WR")
            {
                string lsStrDefaultApplyMarkingsRegKey = lsStrSoftwareRunning == "ConsoleApp1.exe" ? @"SOFTWARE\WOW6432Node\TITUS\CustomFunctions\Content.Extensibility" : @"SOFTWARE\TITUS\CustomFunctions\Content.Extensibility";
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(lsStrDefaultApplyMarkingsRegKey))
                {
                    key.SetValue("DefaultApplyMarkings", "red");
                }

                //string registryValue = string.Empty;
                //RegistryKey localKey = null;
                //if (Environment.Is64BitOperatingSystem)
                //{
                //    localKey = RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.CurrentUser, RegistryView.Registry64);
                //}
                //else
                //{
                //    localKey = RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.CurrentUser, RegistryView.Registry32);
                //}

                //try
                //{
                //    Console.WriteLine(lsStrParameter1);
                //    Console.WriteLine(lsStrParameter2);
                //    // SOFTWARE\Titus Labs\Custom Conditions2\Content.Extensibility
                //    // @"SOFTWARE\\Policies\\TITUS\\ServiceLocation"
                //    //lsStrParameter1 = @"SOFTWARE\\Policies\\TITUS";
                //    //lsStrParameter2 = "Sample";
                //    localKey = localKey.OpenSubKey(lsStrParameter1);
                //    lsStrResult = localKey.GetValue(lsStrParameter2).ToString();
                //}
                //catch (NullReferenceException ex)
                //{
                //    Console.WriteLine(ex.ToString().Substring(0, 84));
                //    if (ex.ToString().Substring(0, 84) == "System.NullReferenceException: Object reference not set to an instance of an object.")
                //    {
                //        // String.Concat($"{lsStrConfigObject}", @" (key != null) evaluates to ", $"True")
                //        lsStrReturnCode = "RR1";
                //        lsStrResult = String.Concat("There appears to be no registry entry for: ", $"{lsStrParameter1}", @"\", $"{lsStrParameter2}");
                //    }
                //    else
                //    {
                //        lsStrMessage = String.Concat(lsStrMessage, "\n", "Looks like the RR function had an exception.");
                //        lsStrMessage = String.Concat(lsStrMessage, "\n", ex);
                //        Log.Error(ex, "Exception is {0}");
                //    }
                //}
                lsBolValidFunction = true;
            }
            if (lsBolValidFunction == false)
            {
                if (lsStrParameter1 == "")
                {
                    lsStrResult = "No function name provided.\n";
                }
                else
                {
                    lsStrResult = "Unknown function name.\n";
                }
                if (lsStrLoggingEnabled.ToUpper() == "TRUE")  // Is Logging enabled?
                {
                    //Log.Debug("lsSt/*r*/Result = {0}", lsStrResult);
                }

                lsStrResult = String.Concat(lsStrResult, "Provide HELP as the first command line parameter\n");
                lsStrResult = String.Concat(lsStrResult, "or as the Function parameter name for the dynamic \n");
                lsStrResult = String.Concat(lsStrResult, "property in the TITUS Administration console.\n");
            }
            if (lsStrLoggingEnabled.ToUpper() == "TRUE")
            {
                if (lsStrExtendedLoggingEnabled == "0")
                {
                    //Log.Debug($"{lsStrConfigObject} The values of some output variables (excluding results) are:");
                }
                else
                {
                    //Log.Debug($"{lsStrConfigObject} The values of all output variables are:");
                }
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "Function               = ", lsStrFunction));
                if (lsStrExtendedLoggingEnabled == "1")
                {
                    //Log.Debug(String.Concat(lsStrConfigObject, " ", "Parameter1             = ", lsStrParameter1));
                    //Log.Debug(String.Concat(lsStrConfigObject, " ", "Parameter2             = ", lsStrParameter2));
                    //Log.Debug(String.Concat(lsStrConfigObject, " ", "Parameter3             = ", lsStrParameter3));
                    //Log.Debug(String.Concat(lsStrConfigObject, " ", "Parameter4             = ", lsStrParameter4));
                    //Log.Debug(String.Concat(lsStrConfigObject, " ", "Parameter5             = ", lsStrParameter5));
                    //Log.Debug(String.Concat(lsStrConfigObject, " ", "Parameter6             = ", lsStrParameter6));
                    //Log.Debug(String.Concat(lsStrConfigObject, " ", "Parameter7             = ", lsStrParameter7));
                    //Log.Debug(String.Concat(lsStrConfigObject, " ", "Parameter8             = ", lsStrParameter8));
                    //Log.Debug(String.Concat(lsStrConfigObject, " ", "Parameter9             = ", lsStrParameter9));
                    //Log.Debug(String.Concat(lsStrConfigObject, " ", "Parameter10            = ", lsStrParameter10));
                    //Log.Debug(String.Concat(lsStrConfigObject, " ", "Parameter11            = ", lsStrParameter11));
                    //Log.Debug(String.Concat(lsStrConfigObject, " ", "Parameter12            = ", lsStrParameter12));
                    //Log.Debug(String.Concat(lsStrConfigObject, " ", "Parameter13            = ", lsStrParameter13));
                    //Log.Debug(String.Concat(lsStrConfigObject, " ", "Parameter14            = ", lsStrParameter14));
                    //Log.Debug(String.Concat(lsStrConfigObject, " ", "Parameter15            = ", lsStrParameter15));
                    //Log.Debug(String.Concat(lsStrConfigObject, " ", "Result                 = ", lsStrResult));
                }
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "ReturnCode             = ", lsStrReturnCode));
                //Log.Debug(String.Concat(lsStrConfigObject, " ", "Message                = ", lsStrMessage));
                //Log.Debug($"{lsStrConfigObject} Version                = {lsStrVersionNo}");
                lsVarEnd = (DateTime.Now - DateTime.MinValue).TotalMilliseconds;
                //Log.Debug($"{lsStrConfigObject} Run time:              = {(lsVarEnd - lsVarStart).ToString()} in milliseconds before log is closed.");
                //Log.Debug($"{lsStrConfigObject} Shutting down");
                //Log.CloseAndFlush();
            }
            #endregion

            //-----------------------------------------------------------------------------------------------------------------------------------------------------//
            //-----------------------------------------   End OF SET WHICH GETS COPIED AS CUSTOM DYNAMIC PROPERTY   -----------------------------------------------//
            //-----------------------------------------------------------------------------------------------------------------------------------------------------//
            resultContainer["Function"] = lsStrFunction;
            resultContainer["Parameter1"] = lsStrParameter1;
            resultContainer["Parameter2"] = lsStrParameter2;
            resultContainer["Parameter3"] = lsStrParameter3;
            resultContainer["Parameter4"] = lsStrParameter4;
            resultContainer["Parameter5"] = lsStrParameter5;
            resultContainer["Parameter6"] = lsStrParameter6;
            resultContainer["Parameter7"] = lsStrParameter7;
            resultContainer["Parameter8"] = lsStrParameter8;
            resultContainer["Parameter9"] = lsStrParameter9;
            resultContainer["Parameter10"] = lsStrParameter10;
            resultContainer["Result"] = lsStrResult;
            resultContainer["ReturnCode"] = lsStrReturnCode;
            resultContainer["Message"] = lsStrMessage;
            resultContainer["Version"] = lsStrVersionNo;
            resultMessage = $"QueryFile.Execute: resultMessage: Success! generated at { DateTime.Now}.";
            resultContainer["Runtime"] = ((DateTime.Now - DateTime.MinValue).TotalMilliseconds - lsVarStart).ToString();
            return true;
        }
        public string Guid => System.Guid.NewGuid().ToString();
        public string Name => GetType().FullName;
        // End of Titus Extension
    }
    /// <summary>
    /// Implements the Luhn algorithm for validating numbers sequences such as credit cards.
    /// </summary>
    internal static class LuhnValidator
    {
        /// <summary>
        /// Validates the input value against the Luhn algorithm.
        /// </summary>
        /// <param name="input">Input string, must be a sequence of numbers.</param>
        /// <returns>True if passes the Luhn algorithm test.</returns>
        internal static bool Validate(string input)
        {
            input = input.Trim();

            int sum = 0;
            bool doubleDigit = false;

            for (int i = input.Length - 1; i >= 0; i--)
            {
                int digit;
                int.TryParse(input[i].ToString(CultureInfo.InvariantCulture), out digit);
                int add = digit * (doubleDigit ? 2 : 1);
                doubleDigit = !doubleDigit;
                sum += add > 9 ? add - 9 : add;
            }

            int checkDigit = (sum % 10) == 0 ? 0 : (10 - (sum % 10));

            return checkDigit == 0;
        }
    }
    class VeraSDK
    {
        public static void ApplyDRM(
              string psStrFileToApplyVeraDRM                        // Parameter 1      File for input to veraSdkSample.exe
            , string psStrVeraGrpToMakeOwner                        // Parameter 2      Vera Group to make owner
            , string psStrVeraPolicyId                              // Parameter 3      Policy Id to use from Vera
            , string psStrTitusVeraWorkFlowWorkingDir               // Parameter 4      [Optional] Defailts to C:\Users\Public\TITUS\Illuminate\Content.Extensibility\VeraTitusWorkflow\
            , string psStrOverwriteExistingDRMFile                  // Parameter 5      [Optional] True is default and cannot be overridden yet.
            , string psStrFileWithVeraDRMApplied                    // Parameter 6      [Optional] Name of file which will have Vera DRM applied, will defailt to psStrFileToApplyVeraDRM to with .html appended. So, test.txt becomes text.txt.html
            , string psStrveraSdkSamplePath                         // Parameter 7      [Optional] Defaults to @"C:\Program Files (x86)\Vera\bin\" if blank
            , string psStrSoftwareRunning)                          // Parameter 8      [Optional] Defauklts to "ConsoleApp1.exe" Indicates whether being by run Content.Extensibility of ConsoleApp1
        {

            //string lsStrReadLine;
            string lsStrDQ = @"""";
            string lsStrArguments = "";
            string lsStrOverwriteExistingDRMFile = "True";
            string lsStrFileWithVeraDRMApplied = string.Concat(psStrFileToApplyVeraDRM, ".html");
            string lsStrVeraSDKpath = psStrveraSdkSamplePath == "" ? @"C:\Program Files (x86)\Vera\bin\" : psStrveraSdkSamplePath;
            string lsStrSoftwareRunning = psStrSoftwareRunning == "" ? "ConsoleApp1.exe" : "True";
            string lsStrFileToApplyVeraDRM = psStrFileToApplyVeraDRM;

            string lsStrVeraGrpToMakeOwner = psStrVeraGrpToMakeOwner;
            string lsStrVeraPolicyId = psStrVeraPolicyId;

            //lsStrFileWithVeraDRMApplied = psStrTitusVeraWorkFlowWorkingDir == "" ? string.Concat(@"C:\Users\Public\TITUS\Illuminate\Content.Extensibility\VeraTitusWorkflow\", lsStrFileWithVeraDRMApplied) : lsStrFileWithVeraDRMApplied;

            Console.WriteLine("\n");
            Console.WriteLine("lsStrFileToApplyVeraDRM           = {0}", lsStrFileToApplyVeraDRM);          // Parameter 1      File for input to veraSdkSample.exe
            Console.WriteLine("psStrVeraGrpToMakeOwner           = {0}", psStrVeraGrpToMakeOwner);          // Parameter 2      Vera Group to make owner
            Console.WriteLine("psStrVeraPolicyId                 = {0}", psStrVeraPolicyId);                // Parameter 3      Policy Id to use from Vera
            Console.WriteLine("psStrTitusVeraWorkFlowWorkingDir  = {0}", psStrTitusVeraWorkFlowWorkingDir); // Parameter 4      [Optional] Defailts to C:\Users\Public\TITUS\Illuminate\Content.Extensibility\VeraTitusWorkflow\
            Console.WriteLine("lsStrOverwriteExistingDRMFile     = {0}", lsStrOverwriteExistingDRMFile);    // Parameter 5      [Optional] True is default and cannot be overridden yet.
            Console.WriteLine("lsStrFileWithVeraDRMApplied       = {0}", lsStrFileWithVeraDRMApplied);      // Parameter 6      [Optional] Name of file which will have Vera DRM applied, will defailt to psStrFileToApplyVeraDRM to with .html appended. So, test.txt becomes text.txt.html
            Console.WriteLine("lsStrveraSdkSamplePath            = {0}", lsStrVeraSDKpath);                 // Parameter 7      [Optional] Defaults to @"C:\Program Files (x86)\Vera\bin\" if blank
            Console.WriteLine("lsStrSoftwareRunning              = {0}", lsStrSoftwareRunning);             // Parameter 8      [Optional] Defauklts to "ConsoleApp1.exe" Indicates whether being by run Content.Extensibility of ConsoleApp1

            DateTime dt = File.GetLastWriteTime(psStrFileToApplyVeraDRM);                                                                                               // Date modified of original file
            Console.WriteLine("About to get key input");
            Console.WriteLine("lsStrFileWithVeraDRMApplied = {0}", lsStrFileWithVeraDRMApplied);
            //lsStrReadLine = Console.ReadLine();
            if (lsStrOverwriteExistingDRMFile == "True")
            {
                File.Delete(lsStrFileWithVeraDRMApplied);
            }

            //
            // Assemble parameters to for verasdksample.exe with input of Parameter1 and writing the results to Parameter2
            //
            lsStrArguments = string.Concat(lsStrArguments, @"/c ", lsStrDQ, lsStrDQ, lsStrVeraSDKpath, "veraSdkSample.exe", lsStrDQ, " ");      // What to call
            lsStrArguments = string.Concat(lsStrArguments, "secure ", lsStrDQ, lsStrFileToApplyVeraDRM, lsStrDQ, " ");                          // method to use
            lsStrArguments = string.Concat(lsStrArguments, lsStrDQ, lsStrFileWithVeraDRMApplied, lsStrDQ, lsStrDQ);                             // File to write to
            if (psStrSoftwareRunning == "ConsoleApp1.exe")
            {
                Console.WriteLine("\n *** \n");
                Console.WriteLine("lsStrFileWithVeraDRMApplied       = {0}", lsStrFileWithVeraDRMApplied);      // Parameter 6      [Optional] Name of file which will have Vera DRM applied, will defailt to psStrFileToApplyVeraDRM to with .html appended. So, test.txt becomes text.txt.html
                Console.WriteLine("lsStrArguments  = \n {0}", lsStrArguments);
            }
            //
            // Run verasdksample.exe with parameters and write output to C:\users\public\TitusVeraIntegrationSDK.log
            //
            String command = lsStrArguments;
            String lsStrVeraCmdLog = @"C:\users\public\TitusVeraIntegrationSDK.log";
            ProcessStartInfo cmdsi = new ProcessStartInfo("cmd.exe");
            cmdsi.Arguments = command;
            cmdsi.RedirectStandardOutput = true; // added xx
            cmdsi.UseShellExecute = false; // added xx
            cmdsi.WorkingDirectory = lsStrVeraSDKpath;
            Process cmd1 = Process.Start(cmdsi);
            cmd1.WaitForExit();
            String lsStrDocId = cmd1.StandardOutput.ReadToEnd().ToString();
            System.IO.File.WriteAllText(lsStrVeraCmdLog, lsStrDocId);
            //
            // Parse out the DocId rcdeturned from verasdksample.
            //
            lsStrDocId = lsStrDocId.Substring(6, 36); // should change this to: https://stackoverflow.com/questions/44264926/extract-guid-from-line-in-c-sharp 
            Console.WriteLine("lsStrDocId = {0}", lsStrDocId);
            //
            // Now we need to add the group and policy, i.e.
            // cmd /c VeraSdkSample.exe change-access --doc-id:a5df5fb2-7bb7-33f5-914a-c4bd0e344a15 --type:group --name:"HR" --policy-id:d090866c-d981-320f-8543-c564e3dd1686
            //
            //
            //  Assemble the parameters for the docId, group to assign and the policy via return of previous command and other parameters coming in.
            //
            lsStrArguments = "";
            lsStrArguments = string.Concat(lsStrArguments, @"/c ", lsStrDQ, lsStrDQ, lsStrVeraSDKpath, "veraSdkSample.exe", lsStrDQ, " ");
            lsStrArguments = string.Concat(lsStrArguments, "change-access --doc-id:", lsStrDocId, " ");
            lsStrArguments = string.Concat(lsStrArguments, "--type:group --name:", lsStrDQ, lsStrVeraGrpToMakeOwner, lsStrDQ, " ");
            lsStrArguments = string.Concat(lsStrArguments, "--policy-id:", lsStrVeraPolicyId, lsStrDQ, lsStrDQ);
            if (psStrSoftwareRunning == "ConsoleApp1.exe")
            {
                Console.WriteLine("lsStrArguments  = \n {0}", lsStrArguments);
            }
            //
            // run the command for this DocId, assinging this group and policy 
            //
            command = lsStrArguments;
            ProcessStartInfo cmdsi2 = new ProcessStartInfo("cmd.exe");
            cmdsi2.Arguments = command;
            cmdsi2.RedirectStandardOutput = true; // added xx
            cmdsi2.UseShellExecute = false; // added xx

            Console.WriteLine("lsStrVeraSDKpath = {0}", lsStrVeraSDKpath);
            //lsStrReadLine = Console.ReadLine();
            cmdsi2.WorkingDirectory = lsStrVeraSDKpath;
            Process cmd2 = Process.Start(cmdsi2);
            cmd2.WaitForExit();
            String lsStrStdOut = cmd2.StandardOutput.ReadToEnd().ToString();
            string path = lsStrVeraCmdLog;
            using (StreamWriter sw = File.AppendText(path))
            {
                sw.WriteLine(cmd2.StandardOutput.ReadToEnd());
            }
            Console.WriteLine("lsStrStdOut = {0}", lsStrStdOut);

            //lsBolValidFunction = true;

        }
    }
    public static class TextTool
    {
        /// <summary>
        /// Count occurrences of strings.
        /// </summary>
        /// 
        // https://stackoverflow.com/questions/186653/get-the-index-of-the-nth-occurrence-of-a-string
        public static int NthIndexOf(this string target, string value, int n)
        {
            Match m = Regex.Match(target, "((" + Regex.Escape(value) + ").*?){" + n + "}");

            if (m.Success)
                return m.Groups[2].Captures[n - 1].Index;
            else
                return -1;
        }
        public static int CountStringOccurrences(string text, string pattern)
        {
            // Loop through all instances of the string 'text'.
            int count = 0;
            int i = 0;
            while ((i = text.IndexOf(pattern, i)) != -1)
            {
                i += pattern.Length;
                count++;
            }
            return count;
        }
        // https://stackoverflow.com/questions/7574606/left-function-in-c-sharp/7574645
        public static string Left(this string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return value;
            maxLength = Math.Abs(maxLength);

            return (value.Length <= maxLength
                   ? value
                   : value.Substring(0, maxLength)
                   );
        }
        // https://stackoverflow.com/questions/2571716/find-nth-occurrence-of-a-character-in-a-string
        public static int GetNthIndexOfChar(string s, char t, int n)
        {
            int count = 0;
            for (int i = 0; i < s.Length; i++)
            {
                if (s[i] == t)
                {
                    count++;
                    if (count == n)
                    {
                        return i;
                    }
                }
            }
            return -1;
        }
        public static string GetRegistryKey(string psStrSubKey, string psStrKeyName)
        {
            // Registry format is copied from location bar at top of RegEdit.exe
            // Computer\HKEY_CLASSES_ROOT
            // Computer\HKEY_CURRENT_USER
            // Computer\HKEY_LOCAL_MACHINE
            // Computer\HKEY_USERS
            // Computer\HKEY_CURRENT_CONFIG
            //Log.Debug("Entered GetRegistryKey");
            string lsStrKeyValue = "";
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(psStrSubKey))

                {
                    if (key != null)
                    {
                        Object k = key.GetValue(psStrKeyName);
                        if (k != null)
                        {
                            lsStrKeyValue = k.ToString();
                        }
                    }
                }
            }
            catch  //just for demonstration...it's always best to handle specific exceptions
            {
                //react appropriately
                //Log.Error(ex, String.Concat("Could not read Registry.CurrentUser.OpenSubKey(", psStrSubKey, ") KeyName ", psStrSubKey));
            }
            //Log.Debug("About to return from GetRegistryKey.");
            return lsStrKeyValue;
        }
        public static int ErrorTest(int x, int y)
        {
            return x / y;
        }
    }
    public class UserImpersonation : IDisposable
    {
        /// <summary>
        /// Logon method (check athetification) from advapi32.dll
        /// </summary>
        /// <param name="lpszUserName"></param>
        /// <param name="lpszDomain"></param>
        /// <param name="lpszPassword"></param>
        /// <param name="dwLogonType"></param>
        /// <param name="dwLogonProvider"></param>
        /// <param name="phToken"></param>
        /// <returns></returns>
        [DllImport("advapi32.dll")]
        private static extern bool LogonUser(String lpszUserName,
            String lpszDomain,
            String lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            ref IntPtr phToken);

        /// <summary>
        /// Close
        /// </summary>
        /// <param name="handle"></param>
        /// <returns></returns>
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern bool CloseHandle(IntPtr handle);

        private WindowsImpersonationContext _windowsImpersonationContext;
        private IntPtr _tokenHandle;
        private string _userName;
        private string _domain;
        private string _passWord;

        const int LOGON32_PROVIDER_DEFAULT = 0;
        const int LOGON32_LOGON_INTERACTIVE = 2;

        /// <summary>
        /// Initialize a UserImpersonation
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="domain"></param>
        /// <param name="passWord"></param>
        public UserImpersonation(string userName, string domain, string passWord)
        {
            _userName = userName;
            _domain = domain;
            _passWord = passWord;
        }

        /// <summary>
        /// Valiate the user inforamtion
        /// </summary>
        /// <returns></returns>
        public bool ImpersonateValidUser()
        {
            bool returnValue = LogonUser(_userName, _domain, _passWord,
                    LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
                    ref _tokenHandle);

            if (false == returnValue)
            {
                return false;
            }

            WindowsIdentity newId = new WindowsIdentity(_tokenHandle);
            _windowsImpersonationContext = newId.Impersonate();
            return true;
        }

        #region IDisposable Members

        /// <summary>
        /// Dispose the UserImpersonation connection
        /// </summary>
        public void Dispose()
        {
            if (_windowsImpersonationContext != null)
                _windowsImpersonationContext.Undo();
            if (_tokenHandle != IntPtr.Zero)
                CloseHandle(_tokenHandle);
        }

        #endregion
    }
}
