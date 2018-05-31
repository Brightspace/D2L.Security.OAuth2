using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Development;
using D2L.Security.OAuth2.TestFrameworks;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Services;
using HttpMock;
using Newtonsoft.Json;

namespace D2L.Security.OAuth2.Benchmarks.FullStackValidation {
	internal abstract class FullStackValidationBenchmark : IBenchmark {

		private HttpClient m_httpClient = new HttpClient();
		private IHttpServer m_httpServer = null;

		void IDisposable.Dispose() {
			m_httpClient.Dispose();
			m_httpClient = null;

			m_httpServer.Dispose();
			m_httpServer = null;
		}

		Action IBenchmark.GetRunner() {
			SetUp( out Uri host, out string token, out string id );

			IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator(
				m_httpClient,
				host,
				null
			);

			return delegate {
				validator.ValidateAsync( token ).SafeAsync().GetAwaiter().GetResult();
			};
		}

		protected abstract ITokenSigner GetTokenSigner( IPublicKeyDataProvider p );

		private void SetUp( out Uri host, out string token, out string id ) {
			m_httpServer = HttpMockFactory.Create( out string hostStr );

			host = new Uri( hostStr + "/.well-known/jwks" );

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

			m_httpServer
				.Stub( r => r.Get( "/.well-known/jwks" ) )
				.Return( JsonConvert.SerializeObject( new { keys = new object[] { jwk.ToJwkDto() } } ) )
				.OK();
		}
	}
}
