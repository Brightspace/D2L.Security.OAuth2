using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace D2L.Security.OAuth2.Keys.Default {
	internal class JsonWebKeySet {
		private readonly Uri m_src;
		private readonly List<JsonWebKey> m_keys = new List<JsonWebKey>();

		public JsonWebKeySet( string json, Uri src ) {
			if ( src == null ) {
				throw new ArgumentNullException( "src" );
			}

			m_src = src;

			try {
				var data = JsonConvert.DeserializeObject<Dictionary<string, List<object>>>( json );

				if( !data.ContainsKey( "keys" ) ) {
					throw new JsonWebKeyParseException( "invalid json web key set: missing keys array" );
				}

				List<object> keyObjects = data[ "keys" ];

				foreach( object keyObject in keyObjects ) {
					string keyJson = JsonConvert.SerializeObject( keyObject );
					JsonWebKey key = JsonWebKey.FromJson( keyJson );
					m_keys.Add( key );
				}
			} catch( InvalidOperationException e ) {
				throw new JsonWebKeyParseException( "error parsing jwks", e );
			} catch( JsonReaderException e ) {
				throw new JsonWebKeyParseException( "Couldn't deserialize jwks from: " + json, e );
			}

		}

		internal JsonWebKeySet( JsonWebKey jsonWebKey, Uri src ) {
			m_src = src;
			m_keys.Add( jsonWebKey );
		}

		public bool TryGetKey( Guid keyId, out JsonWebKey key ) {
			foreach( JsonWebKey currentKey in m_keys ) {
				if( currentKey.Id == keyId ) {
					key = currentKey;
					return true;
				}
			}

			key = null;
			return false;
		}

		public IEnumerator<JsonWebKey> GetEnumerator() {
			return m_keys.GetEnumerator();
		}

		public Uri Source { get { return m_src; } }
	}
}