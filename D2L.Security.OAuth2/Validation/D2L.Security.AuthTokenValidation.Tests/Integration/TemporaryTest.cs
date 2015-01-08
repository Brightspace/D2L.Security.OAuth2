using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.AuthTokenValidation.PublicKeys.Implementations;
using NUnit.Framework;

namespace D2L.Security.AuthTokenValidation.Tests.Integration {
	
	[TestFixture]
	class TemporaryTest {

		private const string AUTH_SERVER = "https://phwinsl01.proddev.d2l:44333/core/";

		[Test]
		public void TestConnectivity() {
			DefaultPublicKeyProvider provider = new DefaultPublicKeyProvider( AUTH_SERVER );
			SecurityToken[] tokens = provider._tokens.ToArray();
		}
	}
}
