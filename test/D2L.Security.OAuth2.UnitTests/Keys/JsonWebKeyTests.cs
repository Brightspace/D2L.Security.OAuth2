using System;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Utilities;
using D2L.Services;
using NUnit.Framework;

namespace D2L.Security.OAuth2.Keys {
	[TestFixture]
	internal sealed class JsonWebKeyTests {
		[Test]
		public void FromJson_ParsesStaticRsaKeyWithoutExp() {
			string id = Guid.NewGuid().ToString();
			string example =
				@"{""kid"":""" + id + @""",""kty"":""RSA"",""use"":""sig"",""n"":""piXmF9_L0UO4K5APzHqiOYl_KtVXAgPlVHhUopPztaW_JRh2k9MDeupIA1cAF9S_r5qRBWcA1QaP0nlGalw3jm_fSHvtUYYhwUhF9X6I19VRmv_BX9Ne2budt5dafI9DbNs2Ltq0X_yfM1dUL81vaR0rz7jYaQ5bF2CRQHVCcIhWkik85PG5c1yK__As842WqogBpW8-zsEoB6s53FNpDG37_HsZAAngATmTY1At4O7jC6p-c0KVPDf25oLVMOWQubyVgCE9FlsVxprHWqsXenlnHEmhZfEbFB_5KB6hj2yV77jhvLRslNvyKflFBs6AGCiczNDzmoXH2GV3FAVLFQ"",""e"":""AQAB""}";

			JsonWebKey key = JsonWebKey.FromJson( example );

			Assert.AreEqual( id, key.Id );
			Assert.IsFalse( key.ExpiresAt.HasValue );
		}

		[Test]
		public void FromJson_ParsesStaticRsaKeyWithExp() {
			string id = Guid.NewGuid().ToString();
			long exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
			string example =
				@"{""exp"":" + exp + @",""kid"":""" + id + @""",""kty"":""RSA"",""use"":""sig"",""n"":""piXmF9_L0UO4K5APzHqiOYl_KtVXAgPlVHhUopPztaW_JRh2k9MDeupIA1cAF9S_r5qRBWcA1QaP0nlGalw3jm_fSHvtUYYhwUhF9X6I19VRmv_BX9Ne2budt5dafI9DbNs2Ltq0X_yfM1dUL81vaR0rz7jYaQ5bF2CRQHVCcIhWkik85PG5c1yK__As842WqogBpW8-zsEoB6s53FNpDG37_HsZAAngATmTY1At4O7jC6p-c0KVPDf25oLVMOWQubyVgCE9FlsVxprHWqsXenlnHEmhZfEbFB_5KB6hj2yV77jhvLRslNvyKflFBs6AGCiczNDzmoXH2GV3FAVLFQ"",""e"":""AQAB""}";

			JsonWebKey key = JsonWebKey.FromJson( example );

			Assert.AreEqual( id, key.Id );
			Assert.IsTrue( key.ExpiresAt.HasValue );
			Assert.AreEqual( exp, key.ExpiresAt.Value.ToUnixTimeSeconds() );
		}

		[Test]
		public void FromJson_ParsesStaticRsaKeyWithNullProperties() {
			string id = Guid.NewGuid().ToString();
			string example =
				@"{""kid"":""" + id + @""",""kty"":""RSA"",""use"":null,""n"":""piXmF9_L0UO4K5APzHqiOYl_KtVXAgPlVHhUopPztaW_JRh2k9MDeupIA1cAF9S_r5qRBWcA1QaP0nlGalw3jm_fSHvtUYYhwUhF9X6I19VRmv_BX9Ne2budt5dafI9DbNs2Ltq0X_yfM1dUL81vaR0rz7jYaQ5bF2CRQHVCcIhWkik85PG5c1yK__As842WqogBpW8-zsEoB6s53FNpDG37_HsZAAngATmTY1At4O7jC6p-c0KVPDf25oLVMOWQubyVgCE9FlsVxprHWqsXenlnHEmhZfEbFB_5KB6hj2yV77jhvLRslNvyKflFBs6AGCiczNDzmoXH2GV3FAVLFQ"",""e"":""AQAB"",""d"":null,""p"":null,""dp"":null,""dq"":null,""qi"":null}";

			JsonWebKey key = JsonWebKey.FromJson(example);

			Assert.AreEqual( id, key.Id );
		}

		[Test]
		public void TryParseJsonWebKey_InvalidRsaModulus_ReturnsFalse() {
			string example =
				@"{""kid"":""" + Guid.NewGuid() + @""",""kty"":""RSA"",""use"":""sig"",""n"":""A"",""e"":""AQAB""}";

			bool success = JsonWebKey.TryParseJsonWebKey( example, out var key, out var error, out var exception, out var useEncKey );

			Assert.IsFalse( success );
			Assert.IsNull( key );
			Assert.AreEqual( "RSA modulus (n) is not valid Base64Url data", error );
			Assert.IsNull( exception );
			Assert.IsFalse( useEncKey );
		}

		[Test]
		public void TryParseJsonWebKey_InvalidRsaExponent_ReturnsFalse() {
			string example =
				@"{""kid"":""" + Guid.NewGuid() + @""",""kty"":""RSA"",""use"":""sig"",""e"":""!@#$"",""n"":""piXmF9_L0UO4K5APzHqiOYl_KtVXAgPlVHhUopPztaW_JRh2k9MDeupIA1cAF9S_r5qRBWcA1QaP0nlGalw3jm_fSHvtUYYhwUhF9X6I19VRmv_BX9Ne2budt5dafI9DbNs2Ltq0X_yfM1dUL81vaR0rz7jYaQ5bF2CRQHVCcIhWkik85PG5c1yK__As842WqogBpW8-zsEoB6s53FNpDG37_HsZAAngATmTY1At4O7jC6p-c0KVPDf25oLVMOWQubyVgCE9FlsVxprHWqsXenlnHEmhZfEbFB_5KB6hj2yV77jhvLRslNvyKflFBs6AGCiczNDzmoXH2GV3FAVLFQ""}";

			bool success = JsonWebKey.TryParseJsonWebKey( example, out var key, out var error, out var exception, out var useEncKey );

			Assert.IsFalse( success );
			Assert.IsNull( key );
			Assert.AreEqual( "RSA exponent (e) is not valid Base64Url data", error );
			Assert.IsNull( exception );
			Assert.IsFalse( useEncKey );
		}

		[Test]
		public void FromJson_InvalidRsaModulus_ThrowsJsonWebKeyParseException() {
			string example =
				@"{""kid"":""" + Guid.NewGuid() + @""",""kty"":""RSA"",""use"":""sig"",""n"":""AAAAA"",""e"":""AQAB""}";

			Assert.Throws<JsonWebKeyParseException>( () => JsonWebKey.FromJson( example ) );
		}

		[Test]
		[TestCase( @"{""kid"":""fae33c85-e421-40f5-bebb-8ec8ab778be4"",""kty"":""EC"",""use"":""sig"",""crv"":""P-256"",""x"":""AL09T4hmZ8kGWPSU8mJ-3g3I2kEVZOYhclTWDCNu-0qA"",""y"":""IDCL6vha_57X2KbTO5mkBibZIL7MTi4DGMEDUdM4gnI""}" )]
		[TestCase( @"{""kid"":""fae33c85-e421-40f5-bebb-8ec8ab778be4"",""kty"":""EC"",""use"":""sig"",""crv"":""P-384"",""x"":""AKfOQlLSk7xXUVaU2kkYUWb0ZvSmIQy3DgJqmYu66TBrFXOMIGvvfEc-qKviYhfKpQ"",""y"":""cCrZCHsHNcnSXw1YoFxiL2qTjVEUf7_Cy4vMTt55CyX3xIxFgkNbd-U4oLi_sgVP""}" )]
		[TestCase( @"{""kid"":""fae33c85-e421-40f5-bebb-8ec8ab778be4"",""kty"":""EC"",""use"":""sig"",""crv"":""P-521"",""x"":""APMnS32Z3PMZ1cEO6GKi-9VtdVssHyVCWAWdIJl2yuhlmtDgulS8vZ7yjPokw80P0c4eOxlACNrT_8_FiWY5K0l4"",""y"":""Ad58CFD37NRSVJLEgcrxg4ExYFsDZ6Mv-WKjIz3QUVgHo_FksDQ_ZT-7SaKY1DTU64Xc2F9NQpeAOAWySnJIyIQN""}" )]
		public void FromJson_ParsesStaticEcKeyWithoutExp( string jwk ) {
			JsonWebKey key = JsonWebKey.FromJson( jwk );

			Assert.AreEqual( "fae33c85-e421-40f5-bebb-8ec8ab778be4", key.Id );
			Assert.IsFalse( key.ExpiresAt.HasValue );

			Assert.DoesNotThrow( () => key.ToSecurityToken() );
		}
		[Test]
		[TestCase( @"{""kid"":""fae33c85-e421-40f5-bebb-8ec8ab778be4"",""kty"":""EC"",""crv"":""P-256"",""x"":""AL09T4hmZ8kGWPSU8mJ-3g3I2kEVZOYhclTWDCNu-0qA"",""y"":""IDCL6vha_57X2KbTO5mkBibZIL7MTi4DGMEDUdM4gnI""}" )]
		[TestCase( @"{""kid"":""fae33c85-e421-40f5-bebb-8ec8ab778be4"",""kty"":""EC"",""crv"":""P-384"",""x"":""AKfOQlLSk7xXUVaU2kkYUWb0ZvSmIQy3DgJqmYu66TBrFXOMIGvvfEc-qKviYhfKpQ"",""y"":""cCrZCHsHNcnSXw1YoFxiL2qTjVEUf7_Cy4vMTt55CyX3xIxFgkNbd-U4oLi_sgVP""}" )]
		[TestCase( @"{""kid"":""fae33c85-e421-40f5-bebb-8ec8ab778be4"",""kty"":""EC"",""crv"":""P-521"",""x"":""APMnS32Z3PMZ1cEO6GKi-9VtdVssHyVCWAWdIJl2yuhlmtDgulS8vZ7yjPokw80P0c4eOxlACNrT_8_FiWY5K0l4"",""y"":""Ad58CFD37NRSVJLEgcrxg4ExYFsDZ6Mv-WKjIz3QUVgHo_FksDQ_ZT-7SaKY1DTU64Xc2F9NQpeAOAWySnJIyIQN""}" )]
		public void FromJson_ParsesStaticEcKeyWithoutUse( string jwk ) {
			JsonWebKey key = JsonWebKey.FromJson( jwk );

			Assert.AreEqual( "fae33c85-e421-40f5-bebb-8ec8ab778be4", key.Id );
			Assert.IsFalse( key.ExpiresAt.HasValue );

			Assert.DoesNotThrow( () => key.ToSecurityToken() );
		}

		[Test]
		public void ToJwkDto_EcKey_SerializesExpectedJson() {
			string json =
				@"{""kid"":""fae33c85-e421-40f5-bebb-8ec8ab778be4"",""kty"":""EC"",""use"":""sig"",""crv"":""P-256"",""x"":""AL09T4hmZ8kGWPSU8mJ-3g3I2kEVZOYhclTWDCNu-0qA"",""y"":""IDCL6vha_57X2KbTO5mkBibZIL7MTi4DGMEDUdM4gnI""}";

			JsonWebKey key = JsonWebKey.FromJson( json );

			Assert.AreEqual( json, JsonSerializer.Serialize( key.ToJwkDto() ) );
		}

		[Test]
		public void TryParseJsonWebKey_InvalidEcX_ReturnsFalse() {
			string example =
				@"{""kid"":""" + Guid.NewGuid() + @""",""kty"":""EC"",""use"":""sig"",""crv"":""P-256"",""x"":""AAAAA"",""y"":""IDCL6vha_57X2KbTO5mkBibZIL7MTi4DGMEDUdM4gnI""}";

			bool success = JsonWebKey.TryParseJsonWebKey( example, out var key, out var error, out var exception, out var useEncKey );

			Assert.IsFalse( success );
			Assert.IsNull( key );
			Assert.AreEqual( "EC x coordinate (x) is not valid Base64Url data", error );
			Assert.IsNull( exception );
			Assert.IsFalse( useEncKey );
		}

		[Test]
		public void TryParseJsonWebKey_InvalidEcY_ReturnsFalse() {
			string example =
				@"{""kid"":""" + Guid.NewGuid() + @""",""kty"":""EC"",""use"":""sig"",""crv"":""P-256"",""x"":""AL09T4hmZ8kGWPSU8mJ-3g3I2kEVZOYhclTWDCNu-0qA"",""y"":""AAAAA""}";

			bool success = JsonWebKey.TryParseJsonWebKey( example, out var key, out var error, out var exception, out var useEncKey );

			Assert.IsFalse( success );
			Assert.IsNull( key );
			Assert.AreEqual( "EC y coordinate (y) is not valid Base64Url data", error );
			Assert.IsNull( exception );
			Assert.IsFalse( useEncKey );
		}

		[Test]
		public void FromJson_InvalidEcX_ThrowsJsonWebKeyParseException() {
			string example =
				@"{""kid"":""" + Guid.NewGuid() + @""",""kty"":""EC"",""use"":""sig"",""crv"":""P-256"",""x"":""AAAAA"",""y"":""IDCL6vha_57X2KbTO5mkBibZIL7MTi4DGMEDUdM4gnI""}";

			Assert.Throws<JsonWebKeyParseException>( () => JsonWebKey.FromJson( example ) );
		}

		[Test]
		public async Task FromJson_GeneratedKeyRoundTrips() {
			IPrivateKeyProvider privateKeyProvider = new RsaPrivateKeyProvider(
				new D2LSecurityTokenFactory(
					DateTimeProvider.Instance,
					TimeSpan.FromHours( 1 )
				)
			);

			D2LSecurityToken token = await privateKeyProvider.GetSigningCredentialsAsync().ConfigureAwait( false );
			JsonWebKey expectedKey = token.ToJsonWebKey();

			string expectedJson = JsonSerializer.Serialize( expectedKey.ToJwkDto() );

			JsonWebKey actualKey = JsonWebKey.FromJson( expectedJson );
			string actualJson = JsonSerializer.Serialize( actualKey.ToJwkDto() );

			Assert.AreEqual( expectedKey.Id, actualKey.Id );
			Assert.AreEqual( expectedKey.ExpiresAt.Value.ToUnixTimeSeconds(), actualKey.ExpiresAt.Value.ToUnixTimeSeconds() );
			Assert.AreEqual( expectedJson, actualJson );
		}

		[Test]
		public async Task FromJson_GeneratedECKeyRoundTrips() {
			IPrivateKeyProvider privateKeyProvider = new EcDsaPrivateKeyProvider(
				new D2LSecurityTokenFactory(
					DateTimeProvider.Instance,
					TimeSpan.FromHours( 1 )
				),
				ECCurve.NamedCurves.nistP256
			);

			JsonWebKey expectedKey;
			using( D2LSecurityToken token = await privateKeyProvider.GetSigningCredentialsAsync().ConfigureAwait( false ) ) {
				expectedKey = token.ToJsonWebKey();
			}

			string expectedJson = JsonSerializer.Serialize( expectedKey.ToJwkDto() );

			JsonWebKey actualKey = JsonWebKey.FromJson( expectedJson );
			string actualJson = JsonSerializer.Serialize( actualKey.ToJwkDto() );

			Assert.AreEqual( expectedKey.Id, actualKey.Id );
			Assert.AreEqual( expectedKey.ExpiresAt.Value.ToUnixTimeSeconds(), actualKey.ExpiresAt.Value.ToUnixTimeSeconds() );
			Assert.AreEqual( expectedJson, actualJson );
		}
	}
}
