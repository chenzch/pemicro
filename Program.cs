using System;

namespace pemicro
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Version : " + Pemicro.Version());
            Console.WriteLine("Dll Version : " + Pemicro.GetDllVersion());
            Console.WriteLine("GetEnumeratedNumberOfPort : " + Pemicro.GetEnumeratedNumberOfPort(Pemicro.PEMicroPortType.AUTODETECT).ToString());
            Console.WriteLine("GetPortDescriptorShort : " + Pemicro.GetPortDescriptorShort(Pemicro.PEMicroPortType.AUTODETECT, 1));
            Console.WriteLine("GetPortDescriptor : " + Pemicro.GetPortDescriptor(Pemicro.PEMicroPortType.AUTODETECT, 1));
            Console.WriteLine("GetDeviceList : " + Pemicro.GetDeviceList(null));
            Console.WriteLine("OpenPortByIdentifier : " + Pemicro.OpenPort(Pemicro.PEMicroPortType.AUTODETECT, 1).ToString());
            Pemicro.ResetHardwareInterface();
            Console.WriteLine("CheckCriticalError : " + Pemicro.CheckCriticalError().ToString("X2"));

            Console.WriteLine("SetInterface : " + Pemicro.SetInterface(Pemicro.PEMicroInterfaces.SWD).ToString());
            Pemicro.SetDebugShiftFrequency();
            Console.WriteLine("EnableDebugModule : " + Pemicro.EnableDebugModule().ToString());

            Console.WriteLine("FlushData : " + Pemicro.FlushData().ToString());
            Pemicro.ClosePort();
        }
    }
}
