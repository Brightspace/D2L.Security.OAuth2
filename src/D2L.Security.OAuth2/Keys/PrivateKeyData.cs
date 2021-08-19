using System;

namespace D2L.Security.OAuth2.Keys {
	public sealed class PrivateKeyData {
		internal static class KeyKinds {
			public const string Rsa = "rsa";
			public const string Ecdsa = "ecdsa";
		}

		public PrivateKeyData(
			string id,
			string kind,
			byte[] data,
			DateTimeOffset createdAt,
			DateTimeOffset notBefore,
			DateTimeOffset expiresAt
		) {
			Id = id;
			Kind = kind;
			Data = data;
			CreatedAt = createdAt;
			NotBefore = notBefore;
			ExpiresAt = expiresAt;
		}

		/// <summary>
		/// The jwk "key id"/kid.
		/// </summary>
		public string Id { get; }

		/// <summary>
		/// The kind of key (e.g. RSA)
		/// </summary>
		public string Kind { get; }

		/// <summary>
		/// Kind-specific key data (including the private bits.)
		/// </summary>
		public byte[] Data { get; }

		/// <summary>
		/// The time the key was originally created.
		/// </summary>
		public DateTimeOffset CreatedAt { get; }

		/// <summary>
		/// The key should not be used to sign things before this point. The
		/// gap between CreatedAt and NotBefore allows for jwks caches to
		/// expire and gives opportunity for people to fetch our new key in the
		/// background.
		//
		/// If there are no other keys available in an emergency it is okay
		/// to sign messages with a key that has not reached NotBefore.
		/// </summary>
		public DateTimeOffset NotBefore { get; }

		/// <summary>
		/// Once a key is expired nothing signed by it will validate.
		/// </summary>
		public DateTimeOffset ExpiresAt { get; }
	}
}
