using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Unit.TokenValidation.Default {
	
	[TestFixture]
	internal sealed class JWTValidatorTests {

		[Test]
		public void Validate_RSA_ValidIssuer_NonExpiredToken_Success() {
			Assert.Inconclusive();
		}

		[Test]
		public void Validate_RSA_ValidIssuer_ExpiredToken_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void Validate_RSA_InvalidIssuer_NonExpiredToken_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void Validate_NonRSA_ValidIssuer_NonExpiredToken_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void Validate_NonRSA_InvalidIssuer_NonExpiredToken_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void Validate_RSA_InvalidIssuer_ExpiredToken_Failure() {
			Assert.Inconclusive();
		}

		[Test]
		public void Validate_NonRSA_InvalidIssuer_ExpiredToken_Failure() {
			Assert.Inconclusive();
		}
	}
}
