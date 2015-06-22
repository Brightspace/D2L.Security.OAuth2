using System;
using System.Threading.Tasks;

using D2L.Security.OAuth2.Keys;
using D2L.Security.OAuth2.Keys.Local;
using D2L.Security.OAuth2.Keys.Local.Data;
using D2L.Security.OAuth2.Keys.Local.Default;
using D2L.Security.OAuth2.Utilities;

using Newtonsoft.Json;

using NUnit.Framework;

namespace D2L.Security.OAuth2.Tests.Unit.Keys {
	[TestFixture]
	[Category( "Unit" )]
	internal sealed class JsonWebKeyTests {
		[Test]
		public void FromJson_ParsesStaticRsaKeyWithoutExp() {
			Guid id = Guid.NewGuid();
			string example =
				@"{""kid"":""" + id + @""",""kty"":""RSA"",""use"":""sig"",""n"":""piXmF9_L0UO4K5APzHqiOYl_KtVXAgPlVHhUopPztaW_JRh2k9MDeupIA1cAF9S_r5qRBWcA1QaP0nlGalw3jm_fSHvtUYYhwUhF9X6I19VRmv_BX9Ne2budt5dafI9DbNs2Ltq0X_yfM1dUL81vaR0rz7jYaQ5bF2CRQHVCcIhWkik85PG5c1yK__As842WqogBpW8-zsEoB6s53FNpDG37_HsZAAngATmTY1At4O7jC6p-c0KVPDf25oLVMOWQubyVgCE9FlsVxprHWqsXenlnHEmhZfEbFB_5KB6hj2yV77jhvLRslNvyKflFBs6AGCiczNDzmoXH2GV3FAVLFQ"",""e"":""AQAB""}";

			JsonWebKey key = JsonWebKey.FromJson( example );

			Assert.AreEqual( id, key.Id );
			Assert.IsFalse( key.ExpiresAt.HasValue );
		}

		[Test]
		public void FromJson_ParsesStaticRsaKeyWithExp() {
			Guid id = Guid.NewGuid();
			long exp = DateTime.UtcNow.ToUnixTime();
			string example =
				@"{""exp"":" + exp + @",""kid"":""" + id + @""",""kty"":""RSA"",""use"":""sig"",""n"":""piXmF9_L0UO4K5APzHqiOYl_KtVXAgPlVHhUopPztaW_JRh2k9MDeupIA1cAF9S_r5qRBWcA1QaP0nlGalw3jm_fSHvtUYYhwUhF9X6I19VRmv_BX9Ne2budt5dafI9DbNs2Ltq0X_yfM1dUL81vaR0rz7jYaQ5bF2CRQHVCcIhWkik85PG5c1yK__As842WqogBpW8-zsEoB6s53FNpDG37_HsZAAngATmTY1At4O7jC6p-c0KVPDf25oLVMOWQubyVgCE9FlsVxprHWqsXenlnHEmhZfEbFB_5KB6hj2yV77jhvLRslNvyKflFBs6AGCiczNDzmoXH2GV3FAVLFQ"",""e"":""AQAB""}";

			JsonWebKey key = JsonWebKey.FromJson( example );

			Assert.AreEqual( id, key.Id );
			Assert.IsTrue( key.ExpiresAt.HasValue );
			Assert.AreEqual( exp, key.ExpiresAt.Value.ToUnixTime() );
		}

		[Test]
		public async Task FromJson_GeneratedKeyRoundTrips() {
			IPrivateKeyProvider privateKeyProvider = new PrivateKeyProvider(
#pragma warning disable 618
				new InMemoryPublicKeyDataProvider(),
#pragma warning restore 618
				new DateTimeProvider(),
				keyLifetime: TimeSpan.FromHours(1),
				keyRotationPeriod: TimeSpan.FromMilliseconds( 42 ) );

			D2LSecurityToken token = await privateKeyProvider.GetSigningCredentialsAsync().SafeAsync();
			JsonWebKey expectedKey = token.ToJsonWebKey();

			string expectedJson = JsonConvert.SerializeObject( expectedKey.ToJwkDto() );

			JsonWebKey actualKey = JsonWebKey.FromJson( expectedJson );
			string actualJson = JsonConvert.SerializeObject( actualKey.ToJwkDto() );

			Assert.AreEqual( expectedKey.Id, actualKey.Id );
			Assert.AreEqual( expectedKey.ExpiresAt.Value.ToUnixTime(), actualKey.ExpiresAt.Value.ToUnixTime() );
			Assert.AreEqual( expectedJson, actualJson );
		}
	}
}
