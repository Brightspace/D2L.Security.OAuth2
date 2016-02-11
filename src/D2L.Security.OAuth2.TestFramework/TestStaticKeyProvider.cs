using System;
using System.Security.Cryptography;
using D2L.Security.OAuth2.TestFramework.Properties;

namespace D2L.Security.OAuth2.TestFramework {
	internal static class TestStaticKeyProvider {
		private static readonly RSAParameters m_parameters;
		private static readonly Guid m_testKeyId = new Guid( "FA7C07A8-42C8-4C57-9AF2-CCE10C271033" );

		static TestStaticKeyProvider() {
			using( var provider = new RSACryptoServiceProvider { PersistKeyInCsp = false } ) {
				provider.FromXmlString( Resources.TestRSAParameters );
				m_parameters = provider.ExportParameters( true );
			}
		}

		public static RSAParameters TestRSAParameters {
			get { return m_parameters; }
		}

		public static Guid TestKeyId {
			get { return m_testKeyId; }
		}
	}
}
