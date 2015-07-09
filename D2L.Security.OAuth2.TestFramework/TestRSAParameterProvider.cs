using System.Security.Cryptography;
using D2L.Security.OAuth2.TestFramework.Properties;

namespace D2L.Security.OAuth2.TestFramework {

	internal static class TestRSAParameterProvider {

		static private readonly RSAParameters m_parameters;

		static TestRSAParameterProvider() {
			var provider = new RSACryptoServiceProvider( 2048 ) { PersistKeyInCsp = false };
			provider.FromXmlString( Resources.RSAParameters );

			m_parameters = provider.ExportParameters( true );
		}

		public static RSAParameters RSAParameters {
			get {
				return m_parameters;
			}
		}
	}
}
