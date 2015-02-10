using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using NUnit.Framework;

namespace D2L.Security.BrowserAuthTokens.Tests.Utilities {
	internal static class Assertions {

		internal static void AssertHasClaim( this JwtSecurityToken me, string type, string value ) {
			Claim claim = me.Claims.Where( x => x.Type == type ).FirstOrDefault();
			Assert.IsNotNull( claim );
			Assert.AreEqual( value, claim.Value );
		}

		internal static void AssertDoesNotHaveClaim( this JwtSecurityToken me, string type ) {
			Claim claim = me.Claims.Where( x => x.Type == type ).FirstOrDefault();
			Assert.IsNull( claim );
		}
	}
}
