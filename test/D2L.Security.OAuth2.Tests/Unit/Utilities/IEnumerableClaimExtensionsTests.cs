using System.Collections.Generic;
using System.Security.Claims;

using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Utilities {
	[TestFixture]
	[Category("Unit")]
	internal class IEnumerableClaimExtensionsTests {
		[Test]
		public void HasClaim_EmptyClaims_False() {
			var claims = new List<Claim>();

			bool result = claims.HasClaim( "something" );

			Assert.IsFalse( result );
		}

		[Test]
		public void HasClaim_DoesntHaveClaim_False() {
			var claims = new List<Claim> {
				new Claim( "foo", "bar" )
			};

			bool result = claims.HasClaim( "something" );

			Assert.IsFalse( result );
		}

		[Test]
		public void HasClaim_DoesHaveClaim_True() {
			var claims = new List<Claim> {
				new Claim( "foo", "bar" )
			};

			bool result = claims.HasClaim( "foo" );

			Assert.IsTrue( result );
		}

		[Test]
		public void TryGetClaim_EmptyClaims_False() {
			var claims = new List<Claim>();

			string value;
			bool result = claims.TryGetClaim( "something", out value );

			Assert.IsNull( value );
			Assert.IsFalse( result );
		}

		[Test]
		public void TryGetClaim_DoesntHaveClaim_False() {
			var claims = new List<Claim> {
				new Claim( "foo", "bar" )
			};

			string value;
			bool result = claims.TryGetClaim( "something", out value );

			Assert.IsNull( value );
			Assert.IsFalse( result );
		}

		[Test]
		public void TryGetClaim_HasClaim_True() {
			const string EXPECTED_NAME = "xyz";
			const string EXPECTED_VALUE = "123";
			var claims = new List<Claim> {
				new Claim( "foo", "bar" ),
				new Claim( EXPECTED_NAME, EXPECTED_VALUE )
			};

			string value;
			bool result = claims.TryGetClaim( EXPECTED_NAME, out value );

			Assert.IsTrue( result );
			Assert.AreEqual( EXPECTED_VALUE, value );
		}
	}
}
