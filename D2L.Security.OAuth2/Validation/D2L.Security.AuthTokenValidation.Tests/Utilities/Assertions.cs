using System.Linq;
using D2L.Security.AuthTokenValidation.TokenValidation;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Utilities {
	internal static class Assertions {
		
		internal static void ContainsScopeValue( IValidatedJWT validatedJWT, string scopeValue ) {
			string scopeValueFromClaim = validatedJWT.Claims.First( x => x.Type == "scope" ).Value;
			Assert.AreEqual( scopeValue, scopeValueFromClaim );
		}
	}
}
