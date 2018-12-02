using D2L.Security.OAuth2.Benchmarks.FullStackValidation;

namespace D2L.Security.OAuth2.Benchmarks {
	internal class Program {
		private static void Main( string[] args ) {
			FullStackValidationBenchmarks.Run();

			System.Environment.Exit( 0 );
		}
	}
}
