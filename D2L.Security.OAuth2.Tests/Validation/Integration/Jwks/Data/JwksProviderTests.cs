using D2L.Security.OAuth2.Tests.Mocks;
using D2L.Security.OAuth2.Validation.Jwks.Data;
using HttpMock;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Validation.Integration.Jwks.Data {

	[TestFixture]
	[Category( "Integration" )]
	internal sealed class JwksProviderTests {

		private readonly JwkDto m_goodJwk1 =
			new JwkDto(
				kty: "RSA",
				use: "sig",
				kid: "43fb7e02-12ee-4c3b-a222-216cb17e51ad",
				e: "AQAB",
				n: "8l-7wBzvKIxeEJS29V81jixy3z43cVNZ0ziuc-AymCexU01pyEGV_1JCclXi4QJW8r9KxyJAuMTsujdunpdlXu1dF1pBCfvIvrOu003FzVnBXIZbsRljUkJXCFMNcQA4UBfavbdAvbTEFF4QWA1GmTc6o4hl9o5NIJB7w2ke1vR0ahPAXBw00RzfkSOzorsNihwSoJmatU2aY5Jv_rtQwC2I2gxY_Bz_j3whiAdaa7jwuKFuqNO0-atBuSr01Q3rMLpssdMcKV7YoxgH36vM-iPqSn2qSLRNNaVekW052o_RZqO_B9Yf-rMMhTVLSRD2UggCHNthqvESWidk6VxNSQ"
				);

		private readonly JwkDto m_goodJwk2 =
			new JwkDto(
				kty: "RSA",
				use: "sig",
				kid: "fcb94da8-8d42-4ba7-80e1-fdedf2cfde2f",
				e: "AQAB",
				n: "zJhkrKJBR28GMGWbAAlWRENmn2UyP3s5DAddha0KW9ncntC4OydJpr4KxFUuntN_Tl2KNnczewe5JKLbC60Y5sT29-i4zCUIj8ijoaU14T4YBsmm8D1BBK7dV-4hMghUIbqM_eBiAI9-RuK0Vd9MG3mlxShbqgAw2MrD14_iEkbOB3auFq_szuwG8jmk58sSqaqf1clzrniJZLBHZ8zMHxxrF3Wd3N6DPkyxj_r9F9JI6-aGspqHsXOGHD0zwuk_oNTHzqNQxFcOXDHE6TtWLN58GrCmEcAedUgrzen_GQ08HQKJ7sY3mRCABPEQWsPx9Ef_MuO_Si-RJtZHJyMktw"
				);

		private readonly IJwksProvider m_provider = new JwksProvider();
		private readonly string m_host;
		private readonly IHttpServer m_lms;

		public JwksProviderTests() {
			m_lms = HttpMockFactory.Create( out m_host );
		}

		[TestFixtureTearDown]
		public void TestFixtureTearDown() {
			m_lms.Dispose();
		}
		/*
		 * 
		 * TODO .. these tests were pulled from the Auth service.   There were written against a data provider that
		 * returned JwkDto's .. but in our implementation here the provider just returns string json and it is the security
		 * key provider that create the security key for you from that.   
		 * 
		 * But this seems less testable .. so maybe reconsider going back to how we had it?
		 * 
		[Test]
		async public void RequestJwks_SingleKeyProvided_PropertiesMatch() {

			const string path = "/singleKeyProvided";
			string singleKeyJwksJson = MakeJwksJson( new[] { m_goodJwk1 } );
			MockLmsJwksCall( path ).Return( singleKeyJwksJson ).OK();

			List<JwkDto> jwks = ( await m_provider.RequestJwksAsync( GetEndpoint( path ) ) ).ToList();

			Assert.AreEqual( 1, jwks.Count );

			JwkDto dto = jwks[0];
			Assert.AreEqual( m_goodJwk1.E, dto.E );
			Assert.AreEqual( m_goodJwk1.Kid, dto.Kid );
			Assert.AreEqual( m_goodJwk1.Kty, dto.Kty );
			Assert.AreEqual( m_goodJwk1.N, dto.N );
			Assert.AreEqual( m_goodJwk1.Use, dto.Use );
		}

		[Test]
		async public void RequestJwks_MultipleKeysProvided_KidsMatchExpected() {

			const string path = "/multipleKeysProvided";
			string twoKeyJwksJson = MakeJwksJson( new[] { m_goodJwk1, m_goodJwk2 } );
			MockLmsJwksCall( path ).Return( twoKeyJwksJson ).OK();

			List<JwkDto> result = ( await m_provider.RequestJwksAsync( GetEndpoint( path ) ) ).ToList();

			Assert.AreEqual( 2, result.Count );

			Assert.AreEqual( m_goodJwk1.Kid, result[0].Kid );
			Assert.AreEqual( m_goodJwk2.Kid, result[1].Kid );
		}

		[Test]
		async public void RequestJwks_KtyNotRsa_NotReturned() {

			const string path = "/ktyNotRsa";
			string notRsa = MakeJwksJson( new[] { new JwkDto( "NOT_RSA", "sig", "abc", "def", "ghi" ) } );
			MockLmsJwksCall( path ).Return( notRsa ).OK();

			List<JwkDto> result = ( await m_provider.RequestJwksAsync( GetEndpoint( path ) ) ).ToList();

			Assert.IsEmpty( result );
		}

		[Test]
		async public void RequestJwks_UseNotSig_NotReturned() {

			const string path = "/useNotSig";
			string notSig = MakeJwksJson( new[] { new JwkDto( "RSA", "NOT_SIG", "abc", "def", "ghi" ) } );
			MockLmsJwksCall( path ).Return( notSig ).OK();

			List<JwkDto> result = ( await m_provider.RequestJwksAsync( GetEndpoint( path ) ) ).ToList();

			Assert.IsEmpty( result );
		}

		[Test]
		public void FetchTenantAsync_ReturnsNon2XX_Exception() {

			const string path = "/returnsNon2XX";
			MockLmsJwksCall( path ).WithStatus( HttpStatusCode.Unauthorized );

			Assert.Throws<HttpRequestException>( async () => await m_provider.RequestJwksAsync( GetEndpoint( path ) ) );
		}

		[Test]
		async public void RequestJwks_MissingAndExtraProperties_NoException() {

			const string path = "/missingAndExtraProperties";
			string goodJwksJson = MakeJwksJson( new[] { m_goodJwk1 } );
			string kidPropReplacedWithUnexpectedProp = goodJwksJson.Replace( "kid", "UNEXPECTED_PROPERTY" );
			MockLmsJwksCall( path ).Return( kidPropReplacedWithUnexpectedProp ).OK();

			string jsonResult = ( await m_provider.RequestJwksAsync( GetEndpoint( path ) ) );

			Assert.IsNotEmpty( jsonResult );
		}

		[Test]
		public void RequestJwks_MalformedJson_ThrowsException() {

			const string path = "/malformedJson";
			string goodJwksJson = MakeJwksJson( new[] { m_goodJwk1 } );
			string jwksWithKidPropertyNameRemoved = goodJwksJson.Replace( "\"kid\"", string.Empty );
			MockLmsJwksCall( path ).Return( jwksWithKidPropertyNameRemoved ).OK();

			// TODO .. more specific exception gets thrown here
			Assert.Throws<Exception>( async () => await m_provider.RequestJwksAsync( GetEndpoint( path ) ) );
		}

		[Test]
		async public void RequestJwks_NoKeysProvided_Success() {

			const string path = "/noKeysProvided";
			string noKeysProvidedJwksJson = MakeJwksJson( Enumerable.Empty<JwkDto>() );
			MockLmsJwksCall( path ).Return( noKeysProvidedJwksJson ).OK();

			IEnumerable<JwkDto> result = await m_provider.RequestJwksAsync( GetEndpoint( path ) );

			Assert.IsEmpty( result );
		}

		private RequestHandler MockLmsJwksCall( string path ) {

			return m_lms.Stub(
				x => x.Get( path )
				).AddHeader(
					"cache-control",
					"cache-control: private, max-age=0, no-cache"
				);
		}

		private Uri GetEndpoint( string path ) {
			return new Uri( string.Concat( m_host, path ) );
		}

		private static string MakeJwksJson( IEnumerable<JwkDto> dtos ) {

			List<string> kids = new List<string>();
			foreach( JwkDto dto in dtos ) {
				kids.Add( string.Format( "{{\"kid\":\"{0}\",\"kty\":\"{1}\",\"use\":\"{2}\",\"n\":\"{3}\",\"e\":\"{4}\"}}", dto.Kid, dto.Kty, dto.Use, dto.N, dto.E ) );
			}

			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.Append( "{\"keys\":[" );
			stringBuilder.Append( string.Join( ",", kids ) );
			stringBuilder.Append( "]}" );
			return stringBuilder.ToString();
		}*/
	}
}
