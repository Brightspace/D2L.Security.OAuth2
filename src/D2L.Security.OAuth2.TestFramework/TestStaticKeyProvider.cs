using System.Security.Cryptography;
using D2L.Security.OAuth2.TestFramework.Properties;

namespace D2L.Security.OAuth2.TestFramework {
	internal static class TestStaticKeyProvider {
		private static readonly RSAParameters m_parameters;
		private const string m_testKeyId = "fa7c07a8-42c8-4c57-9af2-cce10c271033";

		static TestStaticKeyProvider() {
			using( var provider = new RSACryptoServiceProvider { PersistKeyInCsp = false } ) {
				provider.FromXmlString( Resources.TestRSAParameters );
				m_parameters = provider.ExportParameters( true );
			}
		}

		public static RSAParameters TestRSAParameters {
			get { return m_parameters; }
		}

		public static string TestKeyId {
			get { return m_testKeyId; }
		}
	}
}
