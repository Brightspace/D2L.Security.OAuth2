using System;
using System.Collections.Generic;
using D2L.Security.OAuth2.Keys.Default;
using Newtonsoft.Json;

namespace D2L.Security.OAuth2.Keys {
	/// <summary>
	/// Json Web Key (JWK) base class
	/// </summary>
	public abstract class JsonWebKey {

		/// <summary>
		/// The name of the key id (kid) property in the JWT
		/// </summary>
		public const string KEY_ID = "kid";

		private readonly string m_id;
		private readonly DateTime? m_expiresAt;

		internal abstract D2LSecurityToken ToSecurityToken();

		/// <summary>
		/// Construct a new <see cref="JsonWebKey"/> instance
		/// </summary>
		/// <param name="id">The key id (kid)</param>
		/// <param name="expiresAt">When the key expires</param>
		protected JsonWebKey( string id, DateTime? expiresAt ) {
			m_id = id;
			m_expiresAt = expiresAt;
		}

		/// <summary>
		/// The key id (kid)
		/// </summary>
		public virtual string Id {
			get { return m_id; }
		}

		/// <summary>
		/// When the key expires
		/// </summary>
		public virtual DateTime? ExpiresAt {
			get { return m_expiresAt; }
		}

		/// <summary>
		/// Converts the <see cref="RsaJsonWebKey"/> into a JWK DTO
		/// </summary>
		/// <returns>A JWK DTO</returns>
		public abstract object ToJwkDto();

		/// <summary>
		/// Deserialize a JWK
		/// </summary>
		/// <param name="json">The json JWK</param>
		/// <returns>A <see cref="JsonWebKey"/></returns>
		public static JsonWebKey FromJson( string json ) {
			var data = JsonConvert.DeserializeObject<Dictionary<string, object>>( json );

			if( !data.ContainsKey( "use" ) ) {
				throw new JsonWebKeyParseException( "missing 'use' parameter in JSON web key" );
			}

			if( data[ "use" ].ToString() != "sig" ) {
				string msg = String.Format( "invalid 'use' value in JSON web key: {0}", data[ "use" ] );
				throw new JsonWebKeyParseException( msg );
			}

			if( !data.ContainsKey( "kty" ) ) {
				throw new JsonWebKeyParseException( "missing 'kty' parameter in JSON web key" );
			}

			if( !data.ContainsKey( "kid" ) ) {
				throw new JsonWebKeyParseException( "missing 'kid' parameter in JSON web key" );
			}

			string id = data[ "kid" ].ToString();
			DateTime? expiresAt = null;
			if( data.ContainsKey( "exp" ) ) {
				long ts = long.Parse( data[ "exp" ].ToString() );
				expiresAt = DateTimeHelpers.FromUnixTime( ts );
			}

			switch( data[ "kty" ].ToString() ) {
				case "RSA":
					if( !data.ContainsKey( "n" ) ) {
						throw new JsonWebKeyParseException( "missing 'n' parameter in RSA JSON web key" );
					}

					if( !data.ContainsKey( "e" ) ) {
						throw new JsonWebKeyParseException( "missing 'e' parameter in RSA JSON web key" );
					}

					if( HasRsaPrivateKeyMaterial( data ) ) {
						throw new JsonWebKeyParseException( "RSA JSON web key has private key material" );
					}

					return new RsaJsonWebKey(
						id: id,
						expiresAt: expiresAt,
						n: data[ "n" ].ToString(),
						e: data[ "e" ].ToString()
					);

				case "EC":
					if( !data.ContainsKey( "crv" ) ) {
						throw new JsonWebKeyParseException( "missing 'crv' parameter in EC JSON web key" );
					}

					if( !data.ContainsKey( "x" ) ) {
						throw new JsonWebKeyParseException( "missing 'x' parameter in EC JSON web key" );
					}

					if( !data.ContainsKey( "y" ) ) {
						throw new JsonWebKeyParseException( "missing 'y' parameter in EC JSON web key" );
					}

					return new EcDsaJsonWebKey(
						id: id,
						expiresAt: expiresAt,
						curve: data[ "crv" ].ToString(),
						x: data[ "x" ].ToString(),
						y: data[ "y" ].ToString()
					);

				default:
					string msg = String.Format( "'{0}' is not a supported JSON eb key type", data[ "kty" ] );
					throw new JsonWebKeyParseException( msg );

			}
		}

		private static bool HasRsaPrivateKeyMaterial( IReadOnlyDictionary<string, object> data ) {
			return data.ContainsKey( "d" )
				|| data.ContainsKey( "p" )
				|| data.ContainsKey( "q" )
				|| data.ContainsKey( "dp" )
				|| data.ContainsKey( "dq" )
				|| data.ContainsKey( "qi" )
				|| data.ContainsKey( "oth" );
		}
	}

	/// <summary>
	/// Exception indicating that a JWK could not be parsed
	/// </summary>
	public class JsonWebKeyParseException : Exception {

		/// <summary>
		/// Constructs a new <see cref="JsonWebKeyParseException"/>
		/// </summary>
		public JsonWebKeyParseException( string msg ) : base( msg ) { }

		/// <summary>
		/// Constructs a new <see cref="JsonWebKeyParseException"/>
		/// </summary>
		public JsonWebKeyParseException( string msg, Exception inner ) : base( msg, inner ) { }
	}
}
