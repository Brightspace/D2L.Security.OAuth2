using System;
using System.Security.Claims;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.UI;
using D2L.Security.OAuth2.Validation.AccessTokens;
using D2L.Security.OAuth2.Validation.Token;
using Moq;

namespace D2L.Security.OAuth2.Tests.Mocks {
	public static class ValidatedTokenMock {

		public static Mock<IValidatedToken> Create(
			DateTime? expiry = null,
			string xsrfClaim = null
		) {

			expiry = expiry ?? DateTime.Now.AddDays( 1 );

			var claims = new List<Claim>();
			if( xsrfClaim != null ) {
				claims.Add(
					new Claim( type: Constants.Claims.XSRF_TOKEN, value: xsrfClaim )
				);
			}

			var mock = new Mock<IValidatedToken>();

			mock.SetupGet( t => t.Expiry ).Returns( expiry.Value );
			mock.SetupGet( t => t.Claims ).Returns( claims );

			return mock;
		}
	}
}
