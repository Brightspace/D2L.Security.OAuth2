using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Tests.Mocks;
using HttpMock;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Integration.Validation.Jwks.Data {
	
	[TestFixture]
	[Category("Integration")]
	public class JwksProviderTests {
		
		private IHttpServer m_jwksServer;
		private string m_host;
		private string m_pathGood = "/wellknown/jwks";
		//private string m_pathBad = "/wellknown/jwksBad";

		[TestFixtureSetUp]
		public void TestFixtureSetUp() {

			m_jwksServer = HttpMockFactory.Create( out m_host );
			Uri uri = new Uri( m_host + m_pathGood );
			
			m_jwksServer.Stub(
				x => x.Get( "/wellknown/jwks" )
			).Return( "{somejson}" );
			



		}

		


	}
}
