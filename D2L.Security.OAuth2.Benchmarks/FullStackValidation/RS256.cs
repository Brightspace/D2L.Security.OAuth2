using D2L.Security.OAuth2.Keys;

namespace D2L.Security.OAuth2.Benchmarks.FullStackValidation {

	internal sealed class RS256 : FullStackValidationBenchmark, IBenchmark {

		protected override ITokenSigner GetTokenSigner( IPublicKeyDataProvider p ) {
			return RsaTokenSignerFactory.Create( p );
		}

	}
}
