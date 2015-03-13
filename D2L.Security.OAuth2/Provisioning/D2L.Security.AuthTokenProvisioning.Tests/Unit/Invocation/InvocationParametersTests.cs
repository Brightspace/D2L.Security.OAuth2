using System.Net;
using D2L.Security.AuthTokenProvisioning.Invocation;
using NUnit.Framework;

namespace D2L.Security.AuthTokenProvisioning.Tests.Unit.Invocation {
	
	[TestFixture]
	internal sealed class InvocationParametersTests {

		[Test]
		public void Constructor_NoScopes() {
			InvocationParameters invocationParams = new InvocationParameters( new string[] { }, null );
			Assert.AreEqual( string.Empty, invocationParams.Scope );
		}

		[Test]
		public void Constructor_OneScope() {
			string scope = "a";
			InvocationParameters invocationParams = new InvocationParameters( new string[] { scope }, null );
			Assert.AreEqual( scope, invocationParams.Scope );
		}

		[Test]
		public void Constructor_ManyScopes() {
			string scope1 = "a";
			string scope2 = "b";
			string expected = WebUtility.UrlEncode( scope1 + " " + scope2 );
			InvocationParameters invocationParams = new InvocationParameters( new string[] { scope1, scope2 }, null );
			Assert.AreEqual( expected, invocationParams.Scope );
		}
	}
}
