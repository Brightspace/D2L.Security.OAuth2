using System;
using System.Collections.Generic;
using BenchmarkDotNet.Attributes;

namespace D2L.Security.OAuth2.Benchmarks.FullStackValidation {
	[CsvMeasurementsExporter, RPlotExporter, RankColumn]
	public class FullStackValidationBenchmarks {

		private readonly IEnumerable<IDisposable> m_disposable;

		private readonly Action es256;
		private readonly Action es384;
		private readonly Action es512;
		private readonly Action rs256;

		public FullStackValidationBenchmarks() {
			IBenchmark es256 = new ES256();
			IBenchmark es384 = new ES384();
			IBenchmark es512 = new ES512();
			IBenchmark rs256 = new RS256();

			this.es256 = es256.GetRunner();
			this.es384 = es384.GetRunner();
			this.es512 = es512.GetRunner();
			this.rs256 = rs256.GetRunner();

			m_disposable = new[] { es256, es384, es512, rs256 };
		}

		[Benchmark]
		public void ES256() => es256();

		[Benchmark]
		public void ES384() => es384();

		[Benchmark]
		public void ES512() => es512();

		[Benchmark]
		public void RS256() => rs256();

		[GlobalCleanup]
		public void Dispose() {
			foreach( IDisposable disposable in m_disposable ) {
				disposable.Dispose();
			}
		}

	}
}
