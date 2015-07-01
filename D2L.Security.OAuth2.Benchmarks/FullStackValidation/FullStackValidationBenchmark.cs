using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using D2L.Security.OAuth2.Keys.Local;
using D2L.Security.OAuth2.Keys.Local.Data;
using D2L.Security.OAuth2.Keys.Local.Default;
using D2L.Security.OAuth2.Validation.AccessTokens;
using Newtonsoft.Json;

namespace D2L.Security.OAuth2.Benchmarks.FullStackValidation {
	internal abstract class FullStackValidationBenchmark : IBenchmark {

		Action IBenchmark.GetRunner() {
			Uri host;
			string token;
			Guid id;
			SetUp( out host, out token, out id );

			IAccessTokenValidator validator = new AccessTokenValidator(
				new D2L.Security.OAuth2.Keys.Remote.PublicKeyProvider(
					new D2L.Security.OAuth2.Keys.Remote.Data.JwksProvider()
				)
			);

			return delegate {
				validator.ValidateAsync( host, token ).SafeAsync().GetAwaiter().GetResult();
			};
		}

		protected abstract IPrivateKeyProvider GetPrivateKeyProvider( IPublicKeyDataProvider p );


		private void SetUp( out Uri host, out string token, out Guid id ) {
			string hostStr;
			var server = HttpMockFactory.Create( out hostStr );

			host = new Uri( hostStr );

			IPublicKeyDataProvider publicKeyDataProvider = new InMemoryPublicKeyDataProvider();
			IPublicKeyProvider publicKeyProvider = new PublicKeyProvider( publicKeyDataProvider, TimeSpan.FromDays( 2 ) );
			IPrivateKeyProvider privateKeyProvider = GetPrivateKeyProvider( publicKeyDataProvider );

			var securityToken = privateKeyProvider.GetSigningCredentialsAsync().SafeAsync().GetAwaiter().GetResult();

			IKeyManager keyManager = new KeyManager( publicKeyProvider, privateKeyProvider );

			token = keyManager
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

			var jwk = publicKeyProvider
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
