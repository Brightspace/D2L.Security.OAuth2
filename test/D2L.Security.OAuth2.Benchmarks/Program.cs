using BenchmarkDotNet.Running;
using D2L.Security.OAuth2.Benchmarks.FullStackValidation;

namespace D2L.Security.OAuth2.Benchmarks {
	class Program {
		static void Main( string[] args ) {
			BenchmarkRunner.Run<FullStackValidationBenchmarks>();
		}
	}
}
