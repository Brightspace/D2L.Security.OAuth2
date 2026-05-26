#nullable enable

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using D2L.Security.OAuth2.Keys.Default;


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
		private readonly DateTimeOffset? m_expiresAt;

		internal abstract D2LSecurityToken ToSecurityToken();

		/// <summary>
		/// Construct a new <see cref="JsonWebKey"/> instance
		/// </summary>
		/// <param name="id">The key id (kid)</param>
		/// <param name="expiresAt">When the key expires</param>
		protected JsonWebKey( string id, DateTimeOffset? expiresAt ) {
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
		public virtual DateTimeOffset? ExpiresAt {
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
			if( !TryParseJsonWebKey( json, out var result, out var error, out var e, out _ ) ) {
				throw new JsonWebKeyParseException( error, e );
			}

			return result;
		}

		public static bool TryParseJsonWebKey(
			string json,
			[NotNullWhen( true )]
			out JsonWebKey? result,
			[NotNullWhen( false )]
			out string? error,
			out Exception? exception,
			out bool useEncKey
		) {
			Dictionary<string, object> data;
			try {
				data = JsonSerializer.Deserialize<Dictionary<string, object>>( json );
			} catch ( JsonException e ) {
				result = null;
				error = "error deserializing JSON web key string";
				exception = e;
				useEncKey = false;
				return false;
			}

			if( data.TryGetValue( "use", out var use ) && use != null && use.ToString() != "sig" ) {
				result = null;
				error = "invalid 'use' value in JSON web key: " + data[ "use" ];
				exception = null;
				useEncKey = use.ToString() == "enc";
				return false;
			}

			if( !data.TryGetValue( "kty", out var kty ) ) {
				result = null;
				error = "missing 'kty' parameter in JSON web key";
				exception = null;
				useEncKey = false;
				return false;
			}

			if( !data.TryGetValue( "kid", out var kid ) ) {
				result = null;
				error = "missing 'kid' parameter in JSON web key";
				exception = null;
				useEncKey = false;
				return false;
			}

			string id = kid.ToString();
			DateTimeOffset? expiresAt = null;
			if( data.TryGetValue( "exp", out var exp ) ) {
				if( !long.TryParse( exp.ToString(), out long ts ) ) {
					result = null;
					error = "invalid 'exp' value in JSON web key: " + exp;
					exception = null;
					useEncKey = false;
					return false;
				}
				expiresAt = DateTimeOffset.FromUnixTimeSeconds( ts );
			}

			switch( kty.ToString() ) {
				case "RSA":
					if( !data.TryGetValue( "n", out var keyN ) ) {
						result = null;
						error = "missing 'n' parameter in RSA JSON web key";
						exception = null;
						useEncKey = false;
						return false;
					}

					if( !data.TryGetValue( "e", out var keyE ) ) {
						result = null;
						error = "missing 'e' parameter in RSA JSON web key";
						exception = null;
						useEncKey = false;
						return false;
					}

					if( HasRsaPrivateKeyMaterial( data ) ) {
						result = null;
						error = "RSA JSON web key has private key material";
						exception = null;
						useEncKey = false;
						return false;
					}

					result = new RsaJsonWebKey(
						id: id,
						expiresAt: expiresAt,
						n: keyN.ToString(),
						e: keyE.ToString()
					);

					error = null;
					exception = null;
					useEncKey = false;

					return true;

				case "EC":
					if( !data.TryGetValue( "crv", out var keyCrv ) ) {
						result = null;
						error = "missing 'crv' parameter in EC JSON web key";
						exception = null;
						useEncKey = false;
						return false;
					}

					if( !data.TryGetValue( "x", out var keyX ) ) {
						result = null;
						error = "missing 'x' parameter in EC JSON web key";
						exception = null;
						useEncKey = false;
						return false;
					}

					if( !data.TryGetValue( "y", out var keyY ) ) {
						result = null;
						error = "missing 'y' parameter in EC JSON web key";
						exception = null;
						useEncKey = false;
						return false;
					}

					result = new EcDsaJsonWebKey(
						id: id,
						expiresAt: expiresAt,
						curve: keyCrv.ToString(),
						x: keyX.ToString(),
						y: keyY.ToString()
					);

					error = null;
					exception = null;
					useEncKey = false;
					return true;

				default:
					result = null;
					error = $"'{kty}' is not a supported JSON web key type";
					exception = null;
					useEncKey = false;
					return false;

			}
		}

		private static bool HasRsaPrivateKeyMaterial( IReadOnlyDictionary<string, object> data ) {
			return ( data.TryGetValue( "d", out var d ) && d != null )
				|| ( data.TryGetValue( "p", out var p ) && p != null )
				|| ( data.TryGetValue( "q", out var q ) && q != null )
				|| ( data.TryGetValue( "dp", out var dp ) && dp != null )
				|| ( data.TryGetValue( "dq", out var dq ) &&  dq != null )
				|| ( data.TryGetValue( "qi", out var qi ) && qi != null )
				|| ( data.TryGetValue( "oth", out var oth ) && oth != null );
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
		public JsonWebKeyParseException( string msg, Exception? inner ) : base( msg, inner ) { }
	}
}
