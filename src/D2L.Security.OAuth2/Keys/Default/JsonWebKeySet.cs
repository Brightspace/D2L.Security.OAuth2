using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using D2L.Security.OAuth2.Utilities;

#if NET6_0
using JsonException = System.Text.Json.JsonException;
#else
using JsonException = Newtonsoft.Json.JsonReaderException;
#endif

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed class JsonWebKeySet {
		private readonly ImmutableArray<JsonWebKey> m_keys;

		public JsonWebKeySet( string json, Uri src ) {
			Source = src ?? throw new ArgumentNullException( nameof( src ) );

			try {
				var data = JsonSerializer.Deserialize<Dictionary<string, object>>( json );

				if( !data.ContainsKey( "keys" ) ) {
					throw new JsonWebKeyParseException( "invalid json web key set: missing keys array" );
				}

				#if NET6_0
				System.Text.Json.JsonElement keysElement = ( System.Text.Json.JsonElement )data["keys"];
				if ( keysElement.ValueKind is not System.Text.Json.JsonValueKind.Array ) {
					throw new JsonWebKeyParseException("invalid json web key set: keys not an array");
				}
				List<System.Text.Json.JsonElement> keyObjects = keysElement.EnumerateArray().ToList();
				#else
				if ( data["keys"] is not IEnumerable<object> keyObjects ) {
					throw new JsonWebKeyParseException( "invalid json web key set: keys not an array" );
				}
				#endif

				var builder = ImmutableArray.CreateBuilder<JsonWebKey>();
				foreach( object keyObject in keyObjects ) {
					string keyJson = JsonSerializer.Serialize( keyObject );
					JsonWebKey key = JsonWebKey.FromJson( keyJson );
					builder.Add( key );
				}
				m_keys = builder.ToImmutable();
			} catch( InvalidOperationException e ) {
				throw new JsonWebKeyParseException( "error parsing jwks", e );
			} catch( JsonException e ) {
				throw new JsonWebKeyParseException( "Couldn't deserialize jwks from: " + json, e );
			}

		}

		internal JsonWebKeySet( JsonWebKey jsonWebKey, Uri src ) {
			Source = src;
			m_keys = ImmutableArray.Create( jsonWebKey );
		}

		public bool TryGetKey( string keyId, out JsonWebKey key ) {
			foreach( JsonWebKey currentKey in m_keys ) {
				if( currentKey.Id.KeyIdEquals( keyId ) ) {
					key = currentKey;
					return true;
				}
			}

			key = null;
			return false;
		}

		public IEnumerator<JsonWebKey> GetEnumerator() {
			return ( m_keys as IEnumerable<JsonWebKey> ).GetEnumerator();
		}

		public Uri Source { get; }
	}
}
