﻿using System;
using System.Net.Http;
using System.Web.Http;
using D2L.Security.OAuth2.Authentication;
using D2L.Services;
using Microsoft.Owin.Hosting;
using Moq;
using NUnit.Framework;
using Owin;
using SimpleLogInterface;

namespace D2L.Security.OAuth2 {
	[SetUpFixture]
	public sealed class SetUpFixture {
		private const long PORT = 8916; // TODO: do this better
		private IDisposable m_disposeHandle;

		[OneTimeSetUp]
		public void BeforeAnyTests() {
			var options = new StartOptions();
			options.Urls.Add( "http://+:" + PORT );

			m_disposeHandle = WebApp.Start( options, OwinStartup );

		}

		[OneTimeTearDown]
		public void AfterAllTests() {
			if( m_disposeHandle != null ) {
				m_disposeHandle.Dispose();
			}
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

			// TODO: adding this globally might suck later depending on what we want to test
			config.Filters.Add( authFilter );

			config.MapHttpAttributeRoutes();

			config.EnsureInitialized();

			appBuilder.UseWebApi( config );
		}
	}
}
