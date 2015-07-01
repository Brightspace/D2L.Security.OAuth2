using System;
using BenchmarkIt;

namespace D2L.Security.OAuth2.Benchmarks.FullStackValidation {
	internal sealed class FullStackValidationBenchmarks {

		private const int WARMUP_ITERATIONS = 1000;
		private static TimeSpan RUNTIME = TimeSpan.FromSeconds( 4 );

		public static void Run() {
			Action RS256 = ( (IBenchmark)new RS256() ).GetRunner();

			Console.WriteLine( typeof( FullStackValidationBenchmarks ).Name );
			Console.WriteLine( string.Format( "Warmup: {0} iterations", WARMUP_ITERATIONS ) );
			Console.WriteLine( string.Format( "Runtime: {0} seconds/benchmark", RUNTIME.Seconds ) );
			Console.WriteLine();

			Benchmark
				.This( "RS256", RS256 )
				.WithWarmup( WARMUP_ITERATIONS )
				.For( RUNTIME.Seconds )
				.Seconds()
				.PrintComparison();
		}

	}
}
