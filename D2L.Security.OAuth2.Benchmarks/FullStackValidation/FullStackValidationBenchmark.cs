using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Keys.Development;
using D2L.Security.OAuth2.Validation.AccessTokens;
using Newtonsoft.Json;

namespace D2L.Security.OAuth2.Benchmarks.FullStackValidation {
	internal abstract class FullStackValidationBenchmark : IBenchmark {

		Action IBenchmark.GetRunner() {
			Uri host;
			string token;
			Guid id;
			SetUp( out host, out token, out id );

			IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator(
				new HttpClient(),
				host
			);

			return delegate {
				validator.ValidateAsync( token ).SafeAsync().GetAwaiter().GetResult();
			};
		}

		protected abstract IPrivateKeyProvider GetPrivateKeyProvider( IPublicKeyDataProvider p );


		private void SetUp( out Uri host, out string token, out Guid id ) {
			string hostStr;
			var server = HttpMockFactory.Create( out hostStr );

			host = new Uri( hostStr );

			IPublicKeyDataProvider publicKeyDataProvider = new InMemoryPublicKeyDataProvider();
			IPrivateKeyProvider privateKeyProvider = GetPrivateKeyProvider( publicKeyDataProvider );

			var securityToken = privateKeyProvider.GetSigningCredentialsAsync().SafeAsync().GetAwaiter().GetResult();

			ITokenSigner tokenSigner = new TokenSigner( privateKeyProvider );

			token = tokenSigner
				.SignAsync( new UnsignedToken(
					"some issuer",
					"some audience",
					new List<Claim>(),
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
