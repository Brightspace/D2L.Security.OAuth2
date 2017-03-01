using System;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using D2L.Services;

namespace D2L.Security.OAuth2.Keys.Default {

	/// <summary>
	/// ECDSA-specific implemention of <see cref="JsonWebKey"/>
	/// </summary>
	internal sealed partial class EcDsaJsonWebKey : JsonWebKey {

		private readonly string m_curve;
		private readonly string m_x;
		private readonly string m_y;

		/// <summary>
		/// Constructs a new <see cref="EcDsaJsonWebKey"/> instance
		/// </summary>
		/// <param name="id">The key id (kid)</param>
		/// <param name="expiresAt">When the key expires</param>
		/// <param name="publicBlob">Blob in <see cref="CngKeyBlobFormat.EccPublicBlob"/> format</param>
		public EcDsaJsonWebKey(
			Guid id,
			DateTime? expiresAt,
			byte[] publicBlob
		) : base( id, expiresAt ) {
			ECCPublicKeyBlobFormatter.Instance.ParsePublicBlob( publicBlob, out m_curve, out m_x, out m_y );
		}

		/// <summary>
		/// Constructs a new <see cref="EcDsaJsonWebKey"/> instance
		/// </summary>
		/// <param name="id">The key id (kid)</param>
		/// <param name="expiresAt">When the key expires</param>
		/// <param name="curve">The name of the Elliptic Curve</param>
		/// <param name="x">The x position of the point on the curve</param>
		/// <param name="y">The y position of the point on the curve</param>
		public EcDsaJsonWebKey(
			Guid id,
			DateTime? expiresAt,
			string curve,
			string x,
			string y
		) : base( id, expiresAt ) {
			m_curve = curve;
			m_x = x;
			m_y = y;
		}

		/// <summary>
		/// Converts the <see cref="EcDsaJsonWebKey"/> into a JWK DTO
		/// </summary>
		/// <returns>A JWK DTO</returns>
		public override object ToJwkDto() {
			if( ExpiresAt.HasValue ) {
				return new {
					kid = Id.ToString(),
					kty = "EC",
					use = "sig",
					crv = m_curve,
					x = m_x,
					y = m_y,
					exp = (long)ExpiresAt.Value.TimeSinceUnixEpoch().TotalSeconds
				};
			}

			return new {
				kid = Id.ToString(),
				kty = "EC",
				use = "sig",
				crv = m_curve,
				x = m_x,
				y = m_y
			};
		}

		private ECDsaCng BuildEcDsaCng() {
			byte[] publicBlob = ECCPublicKeyBlobFormatter.Instance.BuildECCPublicBlob( this );
			using( var cng = CngKey.Import( publicBlob, CngKeyBlobFormat.EccPublicBlob ) ) {
				// ECDs copies the CngKey, hence the using
				var ecDsa = new ECDsaCng( cng );
				return ecDsa;
			}
		}

		internal override D2LSecurityToken ToSecurityToken() {

			var token = new D2LSecurityToken(
				id: Id,
				validFrom: DateTime.UtcNow,
				validTo: ExpiresAt ?? DateTime.UtcNow + Constants.REMOTE_KEY_MAX_LIFETIME,
				keyFactory: () => {
					var cng = BuildEcDsaCng();
					var key = new ECDsaSecurityKey( cng );
					return new Tuple<AsymmetricSecurityKey, IDisposable>( key, key.ECDsa );
				}
			);
			
			return token;
		}
	}
}
