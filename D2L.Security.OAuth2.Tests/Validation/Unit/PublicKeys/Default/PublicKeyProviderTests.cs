using System;
using Moq;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Validation.Token.Tests.Unit.PublicKeys.Default {
	/*
	[TestFixture]
	internal sealed class PublicKeyProviderTests {

		private const string BASE_KEY = "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"P96cUnz1Ag1ihgF47sA-Ze8TlqA\",\"x5t\":\"P96cUnz1Ag1ihgF47sA-Ze8TlqA\",\"e\":\"AQAB\",\"n\":\"n+O5HTvVDsTbqT34sJgJPG/BuvE83aqc4ChCKFTQcrwoyJVZ9T2XJUjAdSuNLd7qf7784rGBmexHWloWcps1E0/UcOr5G0EQFpI9hXkeuQPXVJ3NJTlnW1an8VW5nXlS2b5PMCuTPf/XnTySbTJvgnRHDjyDJz6rWZzdmdNhM/aMr1rXE33FcM7FyKJ51lXK4sJ2EDdq39UZkajW/r5432JcY7QKmUbIk8P+ZFm8quQk9jUad0V4Qia77qtn46P/vo9BMLPovcPZY45hmQrUt0L0gwJiBXdibIEd7CK7VayYG3CXbssxS8kh65TzG1UVchLhtY687hxf/NpTGBNquQ==\",\"x5c\":[\"MIIC/DCCAeigAwIBAgIQBSZNe52PDaNMFh5n8I0gBzAJBgUrDgMCHQUAMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybDAeFw0xNDA4MDEyMTM0NTFaFw0yMDAxMDEwNDAwMDBaMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ/juR071Q7E26k9+LCYCTxvwbrxPN2qnOAoQihU0HK8KMiVWfU9lyVIwHUrjS3e6n++/OKxgZnsR1paFnKbNRNP1HDq+RtBEBaSPYV5HrkD11SdzSU5Z1tWp/FVuZ15Utm+TzArkz3/1508km0yb4J0Rw48gyc+q1mc3ZnTYTP2jK9a1xN9xXDOxciiedZVyuLCdhA3at/VGZGo1v6+eN9iXGO0CplGyJPD/mRZvKrkJPY1GndFeEImu+6rZ+Oj/76PQTCz6L3D2WOOYZkK1LdC9IMCYgV3YmyBHewiu1WsmBtwl27LMUvJIeuU8xtVFXIS4bWOvO4cX/zaUxgTarkCAwEAAaNMMEowSAYDVR0BBEEwP4AQ8ZbpvXP8fwuZdg1earlZE6EZMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybIIQBSZNe52PDaNMFh5n8I0gBzAJBgUrDgMCHQUAA4IBAQBIfvG38kIhQ8Jjy24cVLmLxtmpEEBbgfODSkG4aGFctA+BDpxP1anjY/nYedssFcaDuFHNvJqNqL1vx2YpSST10UyjzD+TnfXPl+ssgpxDcBIeiS5Q0T5AdmFkJVUER5KAHxB3NuPitqODNKMW5I7dCQ2wM9cmttS6JkfrTjCv/SkSEXh9GYBItGqIk1n1Mbkx8nTEc4OSTHau01ofWx+d6+lvEKkIu5Blw3ZmWnLIGfWY+JQtFe8ldfgXHWCh3+wdaDdKhSB3ZLLdfz7zO3Cfg4L+/DFzkK0wLny/jF9yGfqqXv931L7gt75kGrIqXL28C5xErXUa5KPVFqN4xQKU\"]}";
		private const string INVALID_TYPE_KEY = "{\"kty\":\"EC\",\"use\":\"sig\",\"kid\":\"P96cUnz1Ag1ihgF47sA-Ze8TlqA\",\"x5t\":\"P96cUnz1Ag1ihgF47sA-Ze8TlqA\",\"e\":\"AQAB\",\"n\":\"n+O5HTvVDsTbqT34sJgJPG/BuvE83aqc4ChCKFTQcrwoyJVZ9T2XJUjAdSuNLd7qf7784rGBmexHWloWcps1E0/UcOr5G0EQFpI9hXkeuQPXVJ3NJTlnW1an8VW5nXlS2b5PMCuTPf/XnTySbTJvgnRHDjyDJz6rWZzdmdNhM/aMr1rXE33FcM7FyKJ51lXK4sJ2EDdq39UZkajW/r5432JcY7QKmUbIk8P+ZFm8quQk9jUad0V4Qia77qtn46P/vo9BMLPovcPZY45hmQrUt0L0gwJiBXdibIEd7CK7VayYG3CXbssxS8kh65TzG1UVchLhtY687hxf/NpTGBNquQ==\",\"x5c\":[\"MIIC/DCCAeigAwIBAgIQBSZNe52PDaNMFh5n8I0gBzAJBgUrDgMCHQUAMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybDAeFw0xNDA4MDEyMTM0NTFaFw0yMDAxMDEwNDAwMDBaMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ/juR071Q7E26k9+LCYCTxvwbrxPN2qnOAoQihU0HK8KMiVWfU9lyVIwHUrjS3e6n++/OKxgZnsR1paFnKbNRNP1HDq+RtBEBaSPYV5HrkD11SdzSU5Z1tWp/FVuZ15Utm+TzArkz3/1508km0yb4J0Rw48gyc+q1mc3ZnTYTP2jK9a1xN9xXDOxciiedZVyuLCdhA3at/VGZGo1v6+eN9iXGO0CplGyJPD/mRZvKrkJPY1GndFeEImu+6rZ+Oj/76PQTCz6L3D2WOOYZkK1LdC9IMCYgV3YmyBHewiu1WsmBtwl27LMUvJIeuU8xtVFXIS4bWOvO4cX/zaUxgTarkCAwEAAaNMMEowSAYDVR0BBEEwP4AQ8ZbpvXP8fwuZdg1earlZE6EZMBcxFTATBgNVBAMTDGF1dGguZGV2LmQybIIQBSZNe52PDaNMFh5n8I0gBzAJBgUrDgMCHQUAA4IBAQBIfvG38kIhQ8Jjy24cVLmLxtmpEEBbgfODSkG4aGFctA+BDpxP1anjY/nYedssFcaDuFHNvJqNqL1vx2YpSST10UyjzD+TnfXPl+ssgpxDcBIeiS5Q0T5AdmFkJVUER5KAHxB3NuPitqODNKMW5I7dCQ2wM9cmttS6JkfrTjCv/SkSEXh9GYBItGqIk1n1Mbkx8nTEc4OSTHau01ofWx+d6+lvEKkIu5Blw3ZmWnLIGfWY+JQtFe8ldfgXHWCh3+wdaDdKhSB3ZLLdfz7zO3Cfg4L+/DFzkK0wLny/jF9yGfqqXv931L7gt75kGrIqXL28C5xErXUa5KPVFqN4xQKU\"]}";
		private const string ZERO_X5C_KEY = "{kty: \"RSA\",use: \"sig\",kid: \"P96cUnz1Ag1ihgF47sA-Ze8TlqA\",x5t: \"P96cUnz1Ag1ihgF47sA-Ze8TlqA\",e: \"AQAB\",n: \"n+O5HTvVDsTbqT34sJgJPG/BuvE83aqc4ChCKFTQcrwoyJVZ9T2XJUjAdSuNLd7qf7784rGBmexHWloWcps1E0/UcOr5G0EQFpI9hXkeuQPXVJ3NJTlnW1an8VW5nXlS2b5PMCuTPf/XnTySbTJvgnRHDjyDJz6rWZzdmdNhM/aMr1rXE33FcM7FyKJ51lXK4sJ2EDdq39UZkajW/r5432JcY7QKmUbIk8P+ZFm8quQk9jUad0V4Qia77qtn46P/vo9BMLPovcPZY45hmQrUt0L0gwJiBXdibIEd7CK7VayYG3CXbssxS8kh65TzG1UVchLhtY687hxf/NpTGBNquQ==\",x5c: []}";
		private const string MANY_X5C_KEY = "{kty: \"RSA\",use: \"sig\",kid: \"P96cUnz1Ag1ihgF47sA-Ze8TlqA\",x5t: \"P96cUnz1Ag1ihgF47sA-Ze8TlqA\",e: \"AQAB\",n: \"n+O5HTvVDsTbqT34sJgJPG/BuvE83aqc4ChCKFTQcrwoyJVZ9T2XJUjAdSuNLd7qf7784rGBmexHWloWcps1E0/UcOr5G0EQFpI9hXkeuQPXVJ3NJTlnW1an8VW5nXlS2b5PMCuTPf/XnTySbTJvgnRHDjyDJz6rWZzdmdNhM/aMr1rXE33FcM7FyKJ51lXK4sJ2EDdq39UZkajW/r5432JcY7QKmUbIk8P+ZFm8quQk9jUad0V4Qia77qtn46P/vo9BMLPovcPZY45hmQrUt0L0gwJiBXdibIEd7CK7VayYG3CXbssxS8kh65TzG1UVchLhtY687hxf/NpTGBNquQ==\",x5c: [\"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\"]}";

		[Test]
		public void Get_Success() {
			string keysJson = "{\"keys\":[" + BASE_KEY + "]}";
			IPublicKeyProvider provider = MakePublicKeyProvider( keysJson );

			IPublicKey publicKey = provider.Get();
			Assert.IsNotNull( publicKey );
		}

		[Test]
		public void Get_WrongJsonWebKeyCount_Zero_Throws() {
			Helper_Invalid_AssertThrows( "{\"keys\":[]}" );
		}

		[Test]
		public void Get_WrongJsonWebKeyCount_Many_Throws() {
			Helper_Invalid_AssertThrows( "{\"keys\":[" + BASE_KEY + "," + BASE_KEY + "]}" );
		}
		
		[Test]
		public void Get_WrongX5CEntryCount_Zero_Throws() {
			Helper_Invalid_AssertThrows( "{\"keys\":[" + ZERO_X5C_KEY + "]}" );
		}

		[Test]
		public void Get_WrongX5CEntryCount_Many_Throws() {
			Helper_Invalid_AssertThrows( "{\"keys\":[" + MANY_X5C_KEY + "]}" );
		}

		[Test]
		public void Get_WrongJsonWebKeyType_Throws() {
			Helper_Invalid_AssertThrows( "{\"keys\":[" + INVALID_TYPE_KEY + "]}" );
		}

		private IPublicKeyProvider MakePublicKeyProvider( string keysJson ) {
			OpenIdConnectConfiguration configuration = new OpenIdConnectConfiguration();
			configuration.JsonWebKeySet = new JsonWebKeySet( keysJson );
			configuration.Issuer = "dummyissuer";

			Mock<IOpenIdConfigurationFetcher> fetcherMock = new Mock<IOpenIdConfigurationFetcher>();
			fetcherMock.Setup( x => x.Fetch() ).Returns( configuration );

			IPublicKeyProvider provider = new PublicKeyProvider( fetcherMock.Object );
			return provider;
		}

		private void Helper_Invalid_AssertThrows( string keysJson ) {
			IPublicKeyProvider provider = MakePublicKeyProvider( keysJson );
			Assert.Throws<Exception>( () => provider.Get() );
		}
	}*/
}
