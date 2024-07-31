using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using D2L.Security.OAuth2.Utilities;
using Newtonsoft.Json;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed class JsonWebKeySet {
		private readonly ImmutableArray<JsonWebKey> m_keys;

		public JsonWebKeySet( string json, Uri src ) {
			Source = src ?? throw new ArgumentNullException( nameof( src ) );

			try {
				var data = JsonConvert.DeserializeObject<Dictionary<string, List<object>>>( json );

				if( !data.ContainsKey( "keys" ) ) {
					throw new JsonWebKeyParseException( "invalid json web key set: missing keys array" );
				}

				List<object> keyObjects = data["keys"];

				var builder = ImmutableArray.CreateBuilder<JsonWebKey>(
					initialCapacity: keyObjects.Count
				);

				foreach( object keyObject in keyObjects ) {
					string keyJson = JsonConvert.SerializeObject( keyObject );

					if( !JsonWebKey.TryParseJsonWebKey( keyJson, out var key, out var error, out var exception, out var useEncKey ) ) {
						if( useEncKey ) {
							// Just filter out keys meant for encryption
							continue;
						} else {
							throw new JsonWebKeyParseException( error, exception );
						}
					}

					builder.Add( key );
				}
				m_keys = builder.ToImmutable();
			} catch( InvalidOperationException e ) {
				throw new JsonWebKeyParseException( "error parsing jwks", e );
			} catch( JsonReaderException e ) {
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
