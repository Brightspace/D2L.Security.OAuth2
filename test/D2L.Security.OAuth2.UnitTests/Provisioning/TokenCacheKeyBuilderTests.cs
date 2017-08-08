using System;
using System.Linq;
using System.Security.Claims;
using D2L.Security.OAuth2.Scopes;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Provisioning {
	[TestFixture]
	internal sealed class TokenCacheKeyBuilderTests {
		[Test]
		public void BuildKey_EmptyClaimsAndScopes_MatchesExpected() {
			string key = TokenCacheKeyBuilder.BuildKey( new Uri( "https://example.com" ), Enumerable.Empty<Claim>(), Enumerable.Empty<Scope>() );
			Assert.AreEqual( "{\"issuer\":\"https://example.com/\",\"claims\":[],\"scopes\":[]}", key );
		}

		[Test]
		public void BuildKey_UnsortedClaimsAndScopes_ClaimsAndScopesAreSortedAppropriately() {

			Claim[] claims = { new Claim( "xyz", "val3" ), new Claim( "abc", "val1" ), new Claim( "mno", "val2" ) };
			Scope[] scopes = { new Scope( "x", "y", "z" ), new Scope( "a", "b", "c" ), new Scope( "m", "n", "o" ) };

			string key = TokenCacheKeyBuilder.BuildKey( new Uri( "https://example.com" ), claims, scopes );
			Assert.AreEqual( "{\"issuer\":\"https://example.com/\",\"claims\":[{\"name\":\"abc\",\"value\":\"val1\"},{\"name\":\"mno\",\"value\":\"val2\"},{\"name\":\"xyz\",\"value\":\"val3\"}],\"scopes\":[\"a:b:c\",\"m:n:o\",\"x:y:z\"]}", key );
		}

		[Test]
		public void BuildKey_DifferentEndpoint_SameClaimsAndScopes_AreDifferent() {
			string key1 = TokenCacheKeyBuilder.BuildKey( new Uri( "https://example.com/a" ), Enumerable.Empty<Claim>(), Enumerable.Empty<Scope>() );
			string key2 = TokenCacheKeyBuilder.BuildKey( new Uri( "https://example.com/b" ), Enumerable.Empty<Claim>(), Enumerable.Empty<Scope>() );

			Assert.AreNotEqual( key1, key2 );
		}
	}
}
