using System;
using System.Security.Cryptography;
using System.Text;
using D2L.Security.AuthTokenValidation.Default;
using Moq;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Unit.Default {

	[TestFixture]
	internal sealed class AuthTokenValidatorTests {

		[Test]
		public void Test() {

			//string key = "MIIC/DCCAeigAwIBAgIQBSZNe52PDaNMFh5n8I0gBzAJBgUrDgMCHQUAMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybDAeFw0xNDA4MDEyMTM0NTFaFw0yMDAxMDEwNDAwMDBaMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ/juR071Q7E26k9+LCYCTxvwbrxPN2qnOAoQihU0HK8KMiVWfU9lyVIwHUrjS3e6n++/OKxgZnsR1paFnKbNRNP1HDq+RtBEBaSPYV5HrkD11SdzSU5Z1tWp/FVuZ15Utm+TzArkz3/1508km0yb4J0Rw48gyc+q1mc3ZnTYTP2jK9a1xN9xXDOxciiedZVyuLCdhA3at/VGZGo1v6+eN9iXGO0CplGyJPD/mRZvKrkJPY1GndFeEImu+6rZ+Oj/76PQTCz6L3D2WOOYZkK1LdC9IMCYgV3YmyBHewiu1WsmBtwl27LMUvJIeuU8xtVFXIS4bWOvO4cX/zaUxgTarkCAwEAAaNMMEowSAYDVR0BBEEwP4AQ8ZbpvXP8fwuZdg1earlZE6EZMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybIIQBSZNe52PDaNMFh5n8I0gBzAJBgUrDgMCHQUAA4IBAQBIfvG38kIhQ8Jjy24cVLmLxtmpEEBbgfODSkG4aGFctA+BDpxP1anjY/nYedssFcaDuFHNvJqNqL1vx2YpSST10UyjzD+TnfXPl+ssgpxDcBIeiS5Q0T5AdmFkJVUER5KAHxB3NuPitqODNKMW5I7dCQ2wM9cmttS6JkfrTjCv/SkSEXh9GYBItGqIk1n1Mbkx8nTEc4OSTHau01ofWx+d6+lvEKkIu5Blw3ZmWnLIGfWY+JQtFe8ldfgXHWCh3+wdaDdKhSB3ZLLdfz7zO3Cfg4L+/DFzkK0wLny/jF9yGfqqXv931L7gt75kGrIqXL28C5xErXUa5KPVFqN4xQKU";

			//byte[] bytes = new byte[ key.Length * sizeof(char) ];
			//Buffer.BlockCopy( key.ToCharArray(), 0, bytes, 0, bytes.Length );
			//CngKey.
			//CngKey cngKey = CngKey.Import( bytes, new CngKeyBlobFormat() )

			//Mock<IAuthServerPublicKeyProvider> keyProviderMock = new Mock<IAuthServerPublicKeyProvider>();
			//keyProviderMock.Setup( kp => kp.Get() ).Returns( new  );
			//IAuthTokenValidator atv = new AuthTokenValidator();
		}
	}
}
