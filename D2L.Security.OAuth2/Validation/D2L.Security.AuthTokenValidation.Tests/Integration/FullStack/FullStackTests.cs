using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.AuthTokenValidation.TokenValidation;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Integration.FullStack {
	
	[TestFixture]
	internal sealed class FullStackTests {

		private const string AUTH_SERVER = "https://phwinsl01.proddev.d2l:44333/core/";
		private const string JWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlA5NmNVbnoxQWcxaWhnRjQ3c0EtWmU4VGxxQSIsImtpZCI6IlA5NmNVbnoxQWcxaWhnRjQ3c0EtWmU4VGxxQSJ9.eyJjbGllbnRfaWQiOiJsb3Jlc19tYW5hZ2VyX2NsaWVudCIsInNjb3BlIjoiaHR0cHM6Ly9hcGkuYnJpZ2h0c3BhY2UuY29tL2F1dGgvbG9yZXMubWFuYWdlIiwiaXNzIjoiaHR0cHM6Ly9hcGkuZDJsLmNvbS9hdXRoIiwiYXVkIjoiaHR0cHM6Ly9hcGkuZDJsLmNvbS9hdXRoL3Jlc291cmNlcyIsImV4cCI6MTQyMTE2NzExMywibmJmIjoxNDIxMTYzNTEzfQ.PvqwTmf3CkPcMMku9VXVDFx11r79rqm9ziE_7IUxoIfk1HeBCl3TRi4X5W4AeOjbS3DsrBZF4QDGEMbjmVz2zXVQmvLuUlfmwMI9SuwqtmP2EwN87Lmjxn2Jtl-_jcstqQU_v-4FxC7kWK0cPBoI4Ux6uNvFlKvgcdYwkbGQ2r7Mu91KPrfVxKoIouVIp-c7fPcnK7_WjD5NiSPBR2Nt46K-YUFPIPDWMvaj5mWK_WTgFMCCVdohojHyCgKgaE09k34PtbuUxGQsq02SWqORQZFMZrz7vlsprO8ASO2jArJGBmqhJMTPvfmKt-fgZu4rrPpgGWvrOCaFQRdBqNl-VA";

		[Explicit( "The tokens expire hourly" )]
		[Test]
		public void Validate_Success() {
			IJWTValidator validator = JWTValidatorFactory.Create( AUTH_SERVER );
			IClaimsPrincipal claimsPrincipal = validator.Validate( JWT );

			Assert.Inconclusive();
		}
	}
}
