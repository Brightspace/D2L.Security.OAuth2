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
			string jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlA5NmNVbnoxQWcxaWhnRjQ3c0EtWmU4VGxxQSIsImtpZCI6IlA5NmNVbnoxQWcxaWhnRjQ3c0EtWmU4VGxxQSJ9.eyJjbGllbnRfaWQiOiJsb3Jlc19tYW5hZ2VyX2NsaWVudCIsInNjb3BlIjoiaHR0cHM6Ly9hcGkuYnJpZ2h0c3BhY2UuY29tL2F1dGgvbG9yZXMubWFuYWdlIiwiaXNzIjoiaHR0cHM6Ly9hcGkuZDJsLmNvbS9hdXRoIiwiYXVkIjoiaHR0cHM6Ly9hcGkuZDJsLmNvbS9hdXRoL3Jlc291cmNlcyIsImV4cCI6MTQyMDg0OTE0NywibmJmIjoxNDIwODQ1NTQ3fQ.Q6lG4P2lPgtaXStwxZ6U1nqdcetEXj07E0gau6N6eBESOyc3_nFBX-OxnIEMjiog9fX11Lb1wozzuKb_HeuajfRQbxbKX42d1WBho5PXmSM2dLwLc7UnRMj_yDtRYwFIS1Ol4UTagvKbW3zAJhEqearSmv7DW-hSL9ui-Zskk6rRkZjO4WUE0t8_zT_4dwtwZCTIeMM6qKtWMrpegUCvHbTJ7zLEfnVEJ_3OJr1fdEnlZGBV6ivbDsJZ0BqIks6fd-ESA2kt7bgfRD9x0Hkjz_HsZA5gn3e_IKgg4i9eNepbmeDyNus6h41kQI8Pzt9fozl9Gib9AjaKalTlSFe8eg";
			IJWTValidator validator = JWTValidatorFactory.Create();
			IClaimsPrincipal claimsPrincipal;

			Assert.IsTrue( validator.TryValidate( jwt, out claimsPrincipal ) );
		}

		[Explicit]
		[Test]
		public void CanDownloadCert() {
			IPublicKeyProvider provider = PublicKeyProviderFactory.Create();
		}
	}
}
