using System.Security.Cryptography;
using D2L.Security.OAuth2.TestFramework.Properties;

namespace D2L.Security.OAuth2.TestFramework {

	internal static class TestRSAParametersProvider {

		private static readonly RSAParameters m_parameters;

		static TestRSAParametersProvider() {
			using( var provider = new RSACryptoServiceProvider { PersistKeyInCsp = false } ) {
				provider.FromXmlString( Resources.TestRSAParameters );
				m_parameters = provider.ExportParameters( true );
			}
		}

		public static RSAParameters TestRSAParameters {
			get { return m_parameters; }
		}

	}
}
