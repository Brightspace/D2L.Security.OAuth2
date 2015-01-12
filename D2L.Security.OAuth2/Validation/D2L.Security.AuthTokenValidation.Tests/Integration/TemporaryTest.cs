using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.AuthTokenValidation.Default;
using D2L.Security.AuthTokenValidation.PublicKeys;
using D2L.Security.AuthTokenValidation.PublicKeys.Default;
using D2L.Security.AuthTokenValidation.TokenValidation;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Integration {
	
	[TestFixture]
	class TemporaryTest {

		private const string AUTH_SERVER = "https://phwinsl01.proddev.d2l:44333/core/";
		private const string JWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlA5NmNVbnoxQWcxaWhnRjQ3c0EtWmU4VGxxQSIsImtpZCI6IlA5NmNVbnoxQWcxaWhnRjQ3c0EtWmU4VGxxQSJ9.eyJjbGllbnRfaWQiOiJsb3Jlc19tYW5hZ2VyX2NsaWVudCIsInNjb3BlIjoiaHR0cHM6Ly9hcGkuYnJpZ2h0c3BhY2UuY29tL2F1dGgvbG9yZXMubWFuYWdlIiwiaXNzIjoiaHR0cHM6Ly9hcGkuZDJsLmNvbS9hdXRoIiwiYXVkIjoiaHR0cHM6Ly9hcGkuZDJsLmNvbS9hdXRoL3Jlc291cmNlcyIsImV4cCI6MTQyMTA5Njk1NywibmJmIjoxNDIxMDkzMzU3fQ.EOdVBnZvClnixmdQPNeQd4_elaXvHevkEEJ-Z8tTPCMPtKf_cMJ78w9V_-NpXFHXq2hhgL85EX90H5Q54bM2a40fobn1k1DYUmXYEMhYUCMmJW7nhHcdmovwJ_k-JwDIwpnwytbubHgQ-HHA8SR-V8Eglh204Kliq5G631L0DPnFFgH20YYHl38v45a60fkCiso3IMAkw145oo4fmcHVfRZaketmjpXQ5q_AkC7-lKLmCC8BDmRdbjSbMHSDMK43Z8jm-9D7hAY2N08JTxWLRHM3zW8x9NDvBPoX9FHL69Jx_GJVFuw0T6ixoon6Ap_QC9WRDgozDWAD32x6dLjcQg";

		[Explicit("The token attempted to be validated expires within an hour")]
		[Test]
		public void TestConnectivity() {
			IJWTValidator validator = JWTValidatorFactory.Create( AUTH_SERVER );
			IClaimsPrincipal claimsPrincipal = validator.Validate( JWT );
		}

		[Explicit( "The token attempted to be validated expires within an hour" )]
		[Test]
		public void TestFullStack() {
			IAuthTokenValidatorFactory factory = new AuthTokenValidatorFactory();
			IAuthTokenValidator validator = factory.Create( new Uri( AUTH_SERVER ) );

			Principal principal = validator.VerifyAndDecode( JWT );
		}
	}
}
