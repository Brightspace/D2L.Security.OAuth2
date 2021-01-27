using System.Net;
using System.Net.Sockets;
using HttpMock;

namespace D2L.Security.OAuth2.TestFrameworks {
	public static class HttpMockFactory {
		public static IHttpServer Create( out string host ) {
			int port = GetFreePort();
			host = string.Format( "http://localhost:{0}", port );
			return HttpMockRepository.At( host );
		}

		private static int GetFreePort() {
			TcpListener tcpListener = new TcpListener( IPAddress.Loopback, 0 );
			tcpListener.Start();
			int port = ( ( IPEndPoint )tcpListener.LocalEndpoint ).Port;
			tcpListener.Stop();
			return port;
		}
	}
}
