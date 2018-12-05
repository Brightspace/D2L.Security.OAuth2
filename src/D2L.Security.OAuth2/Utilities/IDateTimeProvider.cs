using System;

namespace D2L.Security.OAuth2.Utilities {
	internal interface IDateTimeProvider {
		DateTimeOffset UtcNow { get; }
	}
}
