using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Development;
using D2L.Security.OAuth2.TestFrameworks;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Services;
using Newtonsoft.Json;

namespace D2L.Security.OAuth2.Benchmarks.FullStackValidation {
	internal abstract class FullStackValidationBenchmark : IBenchmark {
		Action IBenchmark.GetRunner() {
			SetUp( out Uri host, out string token, out string id );

			IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator(
				new HttpClient(),
				host
			);

			return delegate {
				validator.ValidateAsync( token ).SafeAsync().GetAwaiter().GetResult();
			};
		}

		protected abstract ITokenSigner GetTokenSigner( IPublicKeyDataProvider p );

		private void SetUp( out Uri host, out string token, out string id ) {
			var server = HttpMockFactory.Create( out string hostStr );

			host = new Uri( hostStr );

#pragma warning disable 618
			IPublicKeyDataProvider publicKeyDataProvider = new InMemoryPublicKeyDataProvider();
#pragma warning restore 618
			ITokenSigner tokenSigner = GetTokenSigner( publicKeyDataProvider );

			token = tokenSigner
				.SignAsync( new UnsignedToken(
					"some issuer",
					"some audience",
					new Dictionary<string, object>(),
					DateTime.Now,
					DateTime.Now + TimeSpan.FromDays( 1 )
				) )
				.SafeAsync()
				.GetAwaiter()
				.GetResult();

			var jwk = publicKeyDataProvider
				.GetAllAsync()
				.SafeAsync()
				.GetAwaiter()
				.GetResult()
				.First();

			id = jwk.Id;

			server
				.Stub( r => r.Get( "/.well-known/jwks" ) )
				.Return( JsonConvert.SerializeObject( new { keys = new object[] { jwk.ToJwkDto() } } ) )
				.OK();
		}
	}
}
