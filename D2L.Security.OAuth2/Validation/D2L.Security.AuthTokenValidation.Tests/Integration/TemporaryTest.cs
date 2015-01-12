using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.AuthTokenValidation.PublicKeys;
using D2L.Security.AuthTokenValidation.PublicKeys.Default;
using D2L.Security.AuthTokenValidation.TokenValidation;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Integration {
	
	[TestFixture]
	class TemporaryTest {

		private const string AUTH_SERVER = "https://phwinsl01.proddev.d2l:44333/core/";

		[Explicit]
		[Test]
		public void TestConnectivity() {
			string jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlA5NmNVbnoxQWcxaWhnRjQ3c0EtWmU4VGxxQSIsImtpZCI6IlA5NmNVbnoxQWcxaWhnRjQ3c0EtWmU4VGxxQSJ9.eyJjbGllbnRfaWQiOiJsb3Jlc19tYW5hZ2VyX2NsaWVudCIsInNjb3BlIjoiaHR0cHM6Ly9hcGkuYnJpZ2h0c3BhY2UuY29tL2F1dGgvbG9yZXMubWFuYWdlIiwiaXNzIjoiaHR0cHM6Ly9hcGkuZDJsLmNvbS9hdXRoIiwiYXVkIjoiaHR0cHM6Ly9hcGkuZDJsLmNvbS9hdXRoL3Jlc291cmNlcyIsImV4cCI6MTQyMTA4OTMxNiwibmJmIjoxNDIxMDg1NzE2fQ.Em_hUibZzCpzOQsitezvfagR9VNkUXOdg9Pva6RKp11DVmGEMMsuJZmoIasmAzF_GX_Ki5D9lkRGYpe0V7P4121_6Imd_DDt4InemvRShyswnTCepKrjHdNG-NT2RzLd6LyURyAkkhbSkdnJ88nMDNrcQIQhxyfwPZD6aQp-ZUE9RlJVn1m0rUCyBCjxGySrgqPyvAsD4ujhfsd492taMDyrjlkg_tuqPiJ_9-zOo50TlZZ-VHT8oOu10XtyOGkE5kEsjACJXU-7xc-O01LyVqFeeA_AaCFAX0vhb5Q1gJZ37YDR-gVZRQmWNgAyCjsm9qIAXtbuEFAqbRKQNPy8ow";
			IJWTValidator validator = JWTValidatorFactory.Create( AUTH_SERVER );
			IClaimsPrincipal claimsPrincipal;

			Assert.IsTrue( validator.TryValidate( jwt, out claimsPrincipal ) );
		}

		[Explicit]
		[Test]
		public void CanDownloadCert() {
			IPublicKeyProvider provider = PublicKeyProviderFactory.Create( AUTH_SERVER );
		}
	}
}
