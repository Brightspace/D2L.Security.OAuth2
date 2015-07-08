using System;
using D2L.Security.OAuth2.Provisioning;
using D2L.Security.OAuth2.Scopes;
using NUnit.Framework;

namespace D2L.Security.OAuth2.TestFramework {

	[TestFixture]
	internal sealed class TestAccessTokenProviderTests {

		[Test]
		public async void TestTestAccessTokenProvider()
		{
			IAccessTokenProvider provider = TestAccessTokenProviderFactory.Create("https://auth-dev.proddev.d2l/core/");

			IAccessToken token = await provider.ProvisionAccessTokenAsync(new ClaimSet("ur mom"), new Scope[] { new Scope("*", "*", "*") });

			Console.WriteLine(token.Token);
		}
	}
}
