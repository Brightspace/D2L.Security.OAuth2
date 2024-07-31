using System;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using D2L.Services;

namespace D2L.Security.OAuth2.Keys.Default {

	/// <summary>
	/// ECDSA-specific implemention of <see cref="JsonWebKey"/>
	/// </summary>
	internal sealed partial class EcDsaJsonWebKey : JsonWebKey {

		private readonly ECParameters m_parameters;
		private readonly string m_curve;
		private readonly string m_x;
		private readonly string m_y;

		/// <summary>
		/// Constructs a new <see cref="EcDsaJsonWebKey"/> instance
		/// </summary>
		/// <param name="id">The key id (kid)</param>
		/// <param name="expiresAt">When the key expires</param>
		/// <param name="parameters">Curve point definition</param>
		public EcDsaJsonWebKey(
			string id,
			DateTimeOffset? expiresAt,
			ECParameters parameters
		) : base( id, expiresAt ) {
			m_parameters = parameters;
			(m_curve, m_x, m_y) = ECParametersHelper.ToJose( parameters );
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
			string id,
			DateTimeOffset? expiresAt,
			string curve,
			string x,
			string y
		) : base( id, expiresAt ) {
			m_parameters = ECParametersHelper.FromJose( curve, x, y );
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
					kid = Id,
					kty = "EC",
					use = "sig",
					crv = m_curve,
					x = m_x,
					y = m_y,
					exp = ExpiresAt.Value.ToUnixTimeSeconds()
				};
			}

			return new {
				kid = Id,
				kty = "EC",
				use = "sig",
				crv = m_curve,
				x = m_x,
				y = m_y
			};
		}

		internal override D2LSecurityToken ToSecurityToken() {

			var token = new D2LSecurityToken(
				id: Id,
				validFrom: DateTimeOffset.UtcNow,
				validTo: ExpiresAt ?? DateTimeOffset.UtcNow + Constants.REMOTE_KEY_MAX_LIFETIME,
				keyFactory: () => {
					var ecdsa = ECDsa.Create( m_parameters );
					var key = new ECDsaSecurityKey( ecdsa );
					return new Tuple<AsymmetricSecurityKey, IDisposable>( key, ecdsa );
				}
			);

			return token;
		}
	}
}
