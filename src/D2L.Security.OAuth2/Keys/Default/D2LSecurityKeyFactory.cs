using System;
using D2L.Security.OAuth2.Utilities;
using Microsoft.IdentityModel.Tokens;

namespace D2L.Security.OAuth2.Keys.Default {
	internal sealed class D2LSecurityKeyFactory : ID2LSecurityKeyFactory {

		private readonly IDateTimeProvider m_dateTimeProvider;
		private readonly TimeSpan m_keyLifetime;

		public D2LSecurityKeyFactory(
			IDateTimeProvider dateTimeProvider,
			TimeSpan keyLifetime
		) {
			m_dateTimeProvider = dateTimeProvider;
			m_keyLifetime = keyLifetime;
		}

		D2LSecurityKey ID2LSecurityKeyFactory.Create(
			Func<Tuple<AsymmetricSecurityKey, IDisposable>> keyFactory
		) {
			Guid id = Guid.NewGuid();
			DateTime validFrom = m_dateTimeProvider.UtcNow;
			DateTime validTo = validFrom + m_keyLifetime;

			var result = new D2LSecurityKey(
				id: id,
				validFrom: validFrom,
				validTo: validTo,
				keyFactory: keyFactory
			);

			return result;
		}
	}
}
