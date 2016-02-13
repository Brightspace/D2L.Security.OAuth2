using System;
using System.Collections.Generic;
using System.Security.Claims;
using D2L.Security.OAuth2.Validation.AccessTokens;
using Moq;

namespace D2L.Security.OAuth2.TestUtilities.Mocks {
	public static class AccessTokenMock {
		public static Mock<IAccessToken> Create(
			DateTime? expiry = null
		) {
			expiry = expiry ?? DateTime.UtcNow.AddDays( 1 );

			var claims = new List<Claim>();

			var mock = new Mock<IAccessToken>();

			mock.SetupGet( t => t.Expiry ).Returns( expiry.Value );
			mock.SetupGet( t => t.Claims ).Returns( claims );

			return mock;
		}
	}
}
