using System;

namespace D2L.Security.OAuth2.Benchmarks {
	internal interface IBenchmark : IDisposable {

		Action GetRunner();

	}
}
