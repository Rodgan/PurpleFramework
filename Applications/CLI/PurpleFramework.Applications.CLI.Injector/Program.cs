using PurpleFramework.Libraries.PE.Core;
using PurpleFramework.Libraries.ProcessInjector.Core;
using System;
using System.IO;

namespace PurpleFramework.Applications.CLI.Injector
{
    class Program
    {
        static string sectionName;
        static string peToInjectInto;
        static string resourceToInject;
        static void Main(string[] args)
        {
            if (!int.TryParse(args[0], out int processId))
                return;
            
            var dllPath = args[1]; // @"C:\Users\Akurojin\source\repos\PurpleFramework\Applications\CLI\PurpleFramework.Applications.CLI.Injector\bin\Debug\netcoreapp3.1\Test\InjectableDLL.dll";

            var processInjector = new ProcessInjector();
            processInjector.ProcessInjctorSuccess_Event += ProcessInjector_ProcessInjctorSuccess_Event;
            processInjector.ProcessInjectorError_Event += ProcessInjector_ProcessInjectorError_Event;
            //Libraries.ProcessInjector.Core.Injector.DllInjection(processId, dllPath);

            Console.WriteLine("Injecting DLL...");

            processInjector.DllInjection(processId, dllPath, out _);

            return;

            if (args.Length < 3)
                return;

            var analyzer = new Analyzer();

            sectionName = args[0];
            peToInjectInto = args[1];
            resourceToInject = args[2];

            analyzer.AnalyzerError_Event += Analyzer_AnalyzerError_Event;
            analyzer.AnalyzerSuccess_Event += Analyzer_AnalyzerSuccess_Event;

            analyzer.Analyze(peToInjectInto);
        }

        private static void ProcessInjector_ProcessInjectorError_Event(Exception exception)
        {
            Console.WriteLine("An error occurred.");
            Console.WriteLine(exception.Message);
        }

        private static void ProcessInjector_ProcessInjctorSuccess_Event()
        {
            Console.WriteLine("DLL successfully injected");
        }

        private static void Analyzer_AnalyzerSuccess_Event(Libraries.PE.Core.Templates.PortableExecutable exe)
        {
            Console.WriteLine("Process analyzed");
            bool result = exe.CreateSection(sectionName, File.ReadAllBytes(resourceToInject), Libraries.PE.Core.Templates.SectionTable.CHARACTERISTIC.IMAGE_SCN_MEM_WRITE | Libraries.PE.Core.Templates.SectionTable.CHARACTERISTIC.IMAGE_SCN_MEM_READ);

            if (!result)
            {
                Console.WriteLine($"Could not create the section {sectionName}");
                return;
            }

            exe.InjectCodeInDiskImageAndSaveTo(peToInjectInto);

            Console.WriteLine("Injection completed");
        }

        private static void Analyzer_AnalyzerError_Event(Exception exception)
        {
            Console.WriteLine($"An error occurred: {exception.Message}");
        }
    }
}
