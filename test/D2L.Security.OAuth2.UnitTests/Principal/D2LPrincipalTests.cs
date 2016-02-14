using System;
using Moq;
using NUnit.Framework;
using D2L.Security.OAuth2.Validation.AccessTokens;
using System.Security.Claims;
using System.Collections.Generic;

namespace D2L.Security.OAuth2.Principal {
	[TestFixture]
	internal sealed class D2LPrincipalTests {
		private ID2LPrincipal m_principal;

		[Test]
		public void UserId_ForNonUser_Throws() {
			Setup();

			AssertClaimThrows( () => m_principal.UserId );
		}

		[Test]
		public void ActualUserId_ForNonUser_Throws() {
			Setup();

			AssertClaimThrows( () => m_principal.ActualUserId );
		}

		[Test]
		public void UserId_ForUser() {
			Setup( userId: 169 );

			Assert.AreEqual( 169, m_principal.UserId );
		}

		[Test]
		public void ActualUserId_ForUserNotImpersonating_MatchesUserId() {
			Setup( userId: 169 );

			Assert.AreEqual( 169, m_principal.ActualUserId );
		}

		[Test]
		public void ActualUserId_WhenImpersonating_IsDifferent() {
			Setup( userId: 169, actualUserId: 456 );

			Assert.AreEqual( 456, m_principal.ActualUserId );
		}

		private void Setup(
			long? userId = null,
			long? actualUserId = null
		) {
			var claims = new List<Claim>();
			long? actualUserId2 = null;

			if ( userId.HasValue) {
				claims.Add(
					new Claim(
						Constants.Claims.USER_ID,
						userId.Value.ToString()
					)
				);

				actualUserId2 = userId;
			}

			if ( actualUserId.HasValue ) {
				actualUserId2 = actualUserId;
			}

			if ( actualUserId2.HasValue ) {
				claims.Add(
					new Claim(
						Constants.Claims.ACTUAL_USER_ID,
						actualUserId2.Value.ToString()
					)
				);
			}

			var accessToken = new Mock<IAccessToken>( MockBehavior.Strict );

			accessToken
				.Setup( at => at.Claims )
				.Returns( claims );

			m_principal = new D2LPrincipal( accessToken.Object );
		}

		private void AssertClaimThrows( Func<long> fn ) {
			Assert.Throws<InvalidOperationException>( () => fn() );
		}

	}
}
