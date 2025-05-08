using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Development;
using D2L.Security.OAuth2.Utilities;
using D2L.Security.OAuth2.Validation.AccessTokens;
using RichardSzalay.MockHttp;

namespace D2L.Security.OAuth2.Benchmarks.FullStackValidation {
	internal abstract class FullStackValidationBenchmark : IBenchmark {

		private HttpClient m_httpClient;

		void IDisposable.Dispose() {
			m_httpClient.Dispose();
			m_httpClient = null;
		}

		Action IBenchmark.GetRunner() {
			SetUp( out Uri host, out string token, out string id );

			IAccessTokenValidator validator = AccessTokenValidatorFactory.CreateRemoteValidator(
				m_httpClient,
				host,
				null
			);

			return delegate {
				validator.ValidateAsync( token ).ConfigureAwait( false ).GetAwaiter().GetResult();
			};
		}

		protected abstract ITokenSigner GetTokenSigner( IPublicKeyDataProvider p );

		private void SetUp( out Uri host, out string token, out string id ) {
			var mockHandler = new MockHttpMessageHandler();
			m_httpClient = new HttpClient( mockHandler );

			host = new Uri( "http://localhost/.well-known/jwks" );

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
				.ConfigureAwait( false )
				.GetAwaiter()
				.GetResult();

			var jwk = publicKeyDataProvider
				.GetAllAsync()
				.ConfigureAwait( false )
				.GetAwaiter()
				.GetResult()
				.First();

			id = jwk.Id;

			mockHandler
				.When( "http://localhost/.well-known/jwks" )
				.Respond( "application/json", JsonSerializer.Serialize( new { keys = new object[] { jwk.ToJwkDto() } } ) );
		}
	}
}
