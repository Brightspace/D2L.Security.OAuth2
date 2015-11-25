using System;
using System.Net.Http;
using System.Web.Http;
using Microsoft.Owin.Hosting;
using NUnit.Framework;
using Owin;
using SimpleLogInterface;
using D2L.Services;
using D2L.Security.OAuth2.Authentication;
using Moq;

namespace D2L.Security.OAuth2 {
	[SetUpFixture]
	public sealed class SetUpFixture {
		const long PORT = 8916; // TODO: do this better
		private IDisposable m_disposeHandle;

		[SetUp]
		public void BeforeAnyTests() {
			var options = new StartOptions();
			options.Urls.Add( "http://+:" + PORT );

			m_disposeHandle = WebApp.Start( options, OwinStartup );

		}

		[TearDown]
		public void AfterAllTests() {
			m_disposeHandle.SafeDispose();
		}

		public static HttpClient GetHttpClient() {
			var client = new HttpClient();
			client.BaseAddress = new Uri( "http://localhost:" + PORT );
			return client;
		}

		private void OwinStartup( IAppBuilder appBuilder ) {
			HttpConfiguration config = new HttpConfiguration();

			var authFilter = new OAuth2AuthenticationFilter(
				logProvider: NullLogProvider.Instance,
				requestAuthenticator: TestUtilities.RequestAuthenticator,

				// TODO: it'd be nice to use something that stored the last set ID2LPrincipal that way tests
				// could validate more behaviour
				principalDependencyRegistry: new Mock<ID2LPrincipalDependencyRegistry>( MockBehavior.Loose ).Object
			);

			config.MapHttpAttributeRoutes();
			
			// TODO: adding this globally might suck later depending on what we want to test
			config.Filters.Add( authFilter );

			config.EnsureInitialized();

			appBuilder.UseWebApi( config );
		}
	}
}
