using System;
using D2L.Security.OAuth2.Keys.Default;
using D2L.Security.OAuth2.Utilities;

namespace D2L.Security.OAuth2.Keys {

	/// <summary>
	/// Factory for creating a verified-as-good IPublicKeyDataProvider
	/// </summary>
	public static class PublicKeyDataProviderFactory {

		/// <summary>
		/// Factory method for creating verified <see cref="IPublicKeyDataProvider"/> instances.
		/// </summary>
		/// <param name="publicKeyDataProvider">Local implementation of <see cref="IPublicKeyDataProvider"/></param>
		/// <returns>A new <see cref="IPublicKeyDataProvider"/></returns>
		public static IPublicKeyDataProvider Create(
			IPublicKeyDataProvider publicKeyDataProvider
		) {
			return CreateInternal( publicKeyDataProvider );
		}

		internal static ISanePublicKeyDataProvider CreateInternal(
			IPublicKeyDataProvider publicKeyDataProvider
		) {
			if( publicKeyDataProvider == null ) {
				throw new ArgumentNullException( "publicKeyDataProvider" );
			}

			ISanePublicKeyDataProvider saneProvider = publicKeyDataProvider as ISanePublicKeyDataProvider;
			if( saneProvider == null ) {
				saneProvider = new ExpiringPublicKeyDataProvider( publicKeyDataProvider, DateTimeProvider.Instance );
			}

			return saneProvider;
		}

	}
}
