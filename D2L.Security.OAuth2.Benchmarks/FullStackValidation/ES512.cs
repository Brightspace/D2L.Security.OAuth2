using D2L.Security.OAuth2.Keys;

namespace D2L.Security.OAuth2.Benchmarks.FullStackValidation {

	internal sealed class ES512 : FullStackValidationBenchmark, IBenchmark {

		protected override ITokenSigner GetTokenSigner( IPublicKeyDataProvider p ) {
			return EcDsaTokenSignerFactory.Create(
				p,
				EcDsaTokenSignerFactory.Curve.P521
			);
		}

	}
}
