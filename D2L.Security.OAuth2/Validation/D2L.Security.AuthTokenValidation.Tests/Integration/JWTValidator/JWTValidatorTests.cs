using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.AuthTokenValidation.TokenValidation;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Integration.JWTValidator {
	
	[TestFixture]
	internal sealed class JWTValidatorTests {

		private const string AUTH_SERVER = "https://AAAAAAAphwinsl01.proddev.d2l:44333/core/";
		private const string JWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlA5NmNVbnoxQWcxaWhnRjQ3c0EtWmU4VGxxQSIsImtpZCI6IlA5NmNVbnoxQWcxaWhnRjQ3c0EtWmU4VGxxQSJ9.eyJjbGllbnRfaWQiOiJsb3Jlc19tYW5hZ2VyX2NsaWVudCIsInNjb3BlIjoiaHR0cHM6Ly9hcGkuYnJpZ2h0c3BhY2UuY29tL2F1dGgvbG9yZXMubWFuYWdlIiwiaXNzIjoiaHR0cHM6Ly9hcGkuZDJsLmNvbS9hdXRoIiwiYXVkIjoiaHR0cHM6Ly9hcGkuZDJsLmNvbS9hdXRoL3Jlc291cmNlcyIsImV4cCI6MTQyMTEwMzAyNCwibmJmIjoxNDIxMDk5NDI0fQ.HokChETfLssIbE3fr3iEkwyLQLNAOwS9MRY_zyoiRjlVkPI4A-ilV_eUSEH_Jo92n0d7twuGVO8t2nqLp8G3AoSBaJv-MrOIysderYE1qmRQ3CKJVGLUB8G0Zo_NA23FlQQUGRDTJBE-YaCCwYiK9G_6CKJ-euKKO4adkkFy2nbLYlCd13Pe1i41Kch1DHOicQ-omeYeyjZ3ZQJ-Bzk-bZpfX2bLOP6gSWmI00SlLSyOjxuzxf42IISlZVrjmpLveWBauNdWPJ_lEKrbwicV5L1ugdgetUmiX1Sv_nycWcbtwOkW2sykMDcgLUe4K3bBfaHxdd9wLKLHfVpGB6FQ9Q";

		[Explicit( "The tokens expire hourly" )]
		[Test]
		public void Validate_Success() {
			IJWTValidator validator = JWTValidatorFactory.Create( AUTH_SERVER );
			IClaimsPrincipal claimsPrincipal = validator.Validate( JWT );

			Assert.Inconclusive();
		}
	}
}
