using System;
using System.Security.Cryptography;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Benchmarks.FullStackValidation {

	internal sealed class ES256 : FullStackValidationBenchmark, IBenchmark {

		protected override IPrivateKeyProvider GetPrivateKeyProvider( IPublicKeyDataProvider p ) {
			return new EcDsaPrivateKeyProvider(
				PublicKeyDataProviderFactory.CreateInternal( p ),
				new DateTimeProvider(),
				CngAlgorithm.ECDsaP256,
				TimeSpan.FromDays( 2 ),
				TimeSpan.FromDays( 1 )
			);
		}

	}
}
