using System;
using System.Security.Cryptography;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Benchmarks.FullStackValidation {

	internal sealed class ES384 : FullStackValidationBenchmark, IBenchmark {

		protected override IPrivateKeyProvider GetPrivateKeyProvider( IPublicKeyDataProvider p ) {
			return new EcDsaPrivateKeyProvider(
				PublicKeyDataProviderFactory.CreateInternal( p ),
				new DateTimeProvider(),
				CngAlgorithm.ECDsaP384,
				TimeSpan.FromDays( 2 ),
				TimeSpan.FromDays( 1 )
			);
		}

	}
}
