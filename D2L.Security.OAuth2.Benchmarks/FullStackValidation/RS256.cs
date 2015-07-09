using System;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Benchmarks.FullStackValidation {

	internal sealed class RS256 : FullStackValidationBenchmark, IBenchmark {

		protected override IPrivateKeyProvider GetPrivateKeyProvider( IPublicKeyDataProvider p ) {
			return new PrivateKeyProvider(
				PublicKeyDataProviderFactory.CreateInternal( p ),
				new DateTimeProvider(),
				TimeSpan.FromDays( 2 ),
				TimeSpan.FromDays( 1 )
			);
		}

	}
}
